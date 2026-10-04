// DI3 Local Co-op mod — proxy bink2w32.dll
// Reenvia todos los exports al bink2w32 original (renombrado _bink2w32_orig.dll)
// y lanza un hilo que, al pulsar START en el mando 2, activa el co-op local.
// Solo memoria del proceso en runtime. No toca saves, red ni logros. Reversible.
#include <windows.h>
#include <stdio.h>
#include <stdarg.h>

#define XI_START 0x0010

static HINSTANCE g_self;
static char g_log[MAX_PATH];

static void L(const char* fmt, ...){
    FILE* f = fopen(g_log, "a");
    if(!f) return;
    va_list ap; va_start(ap, fmt); vfprintf(f, fmt, ap); va_end(ap);
    fputc('\n', f); fclose(f);
}

// ============================ SECUENCIA CO-OP ============================
// Direcciones probadas (ImageBase 0x400000; se rebasan al modulo del juego).
#define RVA(x) ((x) - 0x400000)
static void* game_base(void){ return (void*)GetModuleHandleA(NULL); }
static DWORD gp(void* base, DWORD ghidra){ return (DWORD)((BYTE*)base + RVA(ghidra)); }

// scan de heap para el gameLoop (mismo patron que el script Frida)
static void* find_gameloop(void* base){
    DWORD vt0  = gp(base, 0x1D4418C);
    DWORD vt58 = gp(base, 0x1D44180);
    DWORD vt308= gp(base, 0x1D44174);
    DWORD vt378= gp(base, 0x1D43F88);
    MEMORY_BASIC_INFORMATION mbi;
    BYTE* p = NULL;
    while(VirtualQuery(p, &mbi, sizeof(mbi)) == sizeof(mbi)){
        BYTE* region = (BYTE*)mbi.BaseAddress;
        SIZE_T sz = mbi.RegionSize;
        if(mbi.State==MEM_COMMIT && !(mbi.Protect & (PAGE_GUARD|PAGE_NOACCESS)) &&
           (mbi.Protect==PAGE_READWRITE || mbi.Protect==PAGE_WRITECOPY)){
            for(SIZE_T off=0; off+0x37C <= sz; off+=4){
                if(*(DWORD*)(region+off) == vt0){
                    BYTE* o = region+off;
                    if(*(DWORD*)(o+0x58)==vt58 && *(DWORD*)(o+0x308)==vt308 && *(DWORD*)(o+0x378)==vt378)
                        return o;
                }
            }
        }
        p = region + sz;
    }
    return NULL;
}

typedef void (__thiscall *dropin_t)(void*, int);
static int g_coop_done = 0;
static int g_active = 0;         // materializacion activa (tras drop-in)
static int g_hooks_done = 0;

// ---- carga de modelo del personaje de P2 (ruta ActivateChanges) ----
// FUN_00b73060(this=*(DAT_0221ceb8), playerId, itemPtr, force) aplica + carga el modelo.
// item ES UN PUNTERO al objeto de catalogo (item+0xC8 = sku, item+0xD0 -> nombre).
typedef void (__thiscall *applychar_t)(void* self, int playerId, void* item, int force);
static void* g_p2_item = 0;      // puntero de item resuelto para el sku actual de P2
static void* g_pending_item = 0; // item a aplicar (lo consume el hook e01890)
static int   g_cycle_pending = 0;// 1 = re-materializar el cuerpo de P2 con el nuevo personaje
static int mem_ok(void* p, SIZE_T n, int write);   // (definida mas abajo)

// ---- lista DINAMICA de personajes (auto-descubierta en memoria al unirse) ----
// Se escanea el proceso buscando items de catalogo (sku@+0xC8, nombre@+0xD0) en
// el rango de personajes. Asi cubre CUALQUIER mundo/personaje sin lista a mano.
#define MAXCHARS 190
static DWORD g_sku[MAXCHARS];        // sku de cada personaje
static void* g_item[MAXCHARS];       // puntero al item de catalogo
static char  g_name[MAXCHARS][24];   // nombre (del juego) para logs
static int   g_ncyc = 0;             // nº de personajes descubiertos
static int   g_cyc_idx = 0;          // indice actual del ciclador

// resuelve sku -> puntero del item de catalogo (escaneo; correr en hilo worker)
static void* resolve_item_ptr(DWORD sku){
    MEMORY_BASIC_INFORMATION mbi;
    BYTE* p = 0;
    while(VirtualQuery(p, &mbi, sizeof(mbi)) == sizeof(mbi)){
        BYTE* region = (BYTE*)mbi.BaseAddress;
        SIZE_T sz = mbi.RegionSize;
        if(mbi.State==MEM_COMMIT && !(mbi.Protect & (PAGE_GUARD|PAGE_NOACCESS)) &&
           (mbi.Protect==PAGE_READWRITE || mbi.Protect==PAGE_WRITECOPY)){
            BYTE* it;
            for(it = region; it + 0xE0 <= region + sz; it += 4){
                if(*(DWORD*)(it + 0xC8) == sku){
                    DWORD nameptr = *(DWORD*)(it + 0xD0);
                    if(nameptr > 0x10000){
                        MEMORY_BASIC_INFORMATION m2;
                        if(VirtualQuery((void*)nameptr, &m2, sizeof(m2))==sizeof(m2) &&
                           m2.State==MEM_COMMIT && !(m2.Protect & (PAGE_GUARD|PAGE_NOACCESS))){
                            BYTE c0 = *(BYTE*)nameptr;
                            if(c0 >= 0x20 && c0 < 0x7f) return it;   // item valido
                        }
                    }
                }
            }
        }
        p = region + sz;
    }
    return 0;
}

// Descubre TODOS los personajes cargados (una pasada por memoria, dedup por sku).
static void scan_characters(void){
    g_ncyc = 0;
    MEMORY_BASIC_INFORMATION mbi;
    BYTE* p = 0;
    while(VirtualQuery(p, &mbi, sizeof(mbi)) == sizeof(mbi)){
        BYTE* region = (BYTE*)mbi.BaseAddress;
        SIZE_T sz = mbi.RegionSize;
        if(mbi.State==MEM_COMMIT && !(mbi.Protect & (PAGE_GUARD|PAGE_NOACCESS)) &&
           (mbi.Protect==PAGE_READWRITE || mbi.Protect==PAGE_WRITECOPY)){
            BYTE* it;
            for(it = region; it + 0xE0 <= region + sz; it += 4){
                DWORD sku = *(DWORD*)(it + 0xC8);
                if(sku >= 0xf4000 && sku < 0xf5000){
                    DWORD nameptr = *(DWORD*)(it + 0xD0);
                    if(nameptr > 0x10000 && mem_ok((void*)nameptr, 1, 0) &&
                       (*(BYTE*)nameptr) >= 0x20 && (*(BYTE*)nameptr) < 0x7f){
                        int dup = 0;
                        for(int i=0;i<g_ncyc;i++) if(g_sku[i]==sku){ dup=1; break; }
                        if(!dup && g_ncyc < MAXCHARS){
                            g_sku[g_ncyc]  = sku;
                            g_item[g_ncyc] = it;
                            // copiar el nombre SOLO si hay 24 bytes legibles (evita leer de mas)
                            if(mem_ok((void*)nameptr, 24, 0))
                                lstrcpynA(g_name[g_ncyc], (const char*)nameptr, sizeof(g_name[0]));
                            else
                                g_name[g_ncyc][0] = 0;
                            g_ncyc++;
                        }
                    }
                }
            }
        }
        p = region + sz;
    }
    L("[coop] %d personajes descubiertos", g_ncyc);
}

#define P2_SKU_DEFAULT 0xf431d   // Mickey (por defecto)
#define POSX   0x10000
static DWORD g_p2_sku = P2_SKU_DEFAULT;

// Lee el SKU del personaje de P2 desde  coop_p2.txt  (junto al DLL).
// Formato: un numero hex, p.ej.  0xf431d   o   f431d   (Mickey).
static void read_p2_sku(void){
    char path[MAX_PATH];
    lstrcpynA(path, g_log, MAX_PATH);
    char* p = strrchr(path, '\\');
    if(p) strcpy(p+1, "coop_p2.txt"); else strcpy(path, "coop_p2.txt");
    FILE* f = fopen(path, "r");
    if(!f){ L("[coop] sin coop_p2.txt -> P2 = Mickey (0x%x)", g_p2_sku); return; }
    char buf[64] = {0};
    if(fgets(buf, sizeof(buf), f)){
        unsigned long v = strtoul(buf, NULL, 16);   // acepta "0xNNNN" o "NNNN"
        if(v != 0 && v != 0xfffffffful) g_p2_sku = (DWORD)v;
    }
    fclose(f);
    L("[coop] P2 SKU (coop_p2.txt) = 0x%x", g_p2_sku);
}

// ---- infra de hooks inline (trampolin) ----
void* g_tramp_e01890 = 0;
void* g_tramp_solidify = 0;

static void* install_hook(void* target, void* detour, int copylen, void** slot){
    BYTE* tramp = (BYTE*)VirtualAlloc(0, copylen + 5, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if(!tramp) return 0;
    memcpy(tramp, target, copylen);
    tramp[copylen] = 0xE9;
    *(DWORD*)(tramp + copylen + 1) = (DWORD)((BYTE*)target + copylen) - (DWORD)(tramp + copylen + 5);
    if(slot) *slot = tramp;   // publicar el trampolin ANTES de parchear (evita carrera)
    DWORD old;
    VirtualProtect(target, copylen, PAGE_EXECUTE_READWRITE, &old);
    ((BYTE*)target)[0] = 0xE9;
    *(DWORD*)((BYTE*)target + 1) = (DWORD)detour - ((DWORD)target + 5);
    for(int i=5;i<copylen;i++) ((BYTE*)target)[i] = 0x90;
    VirtualProtect(target, copylen, old, &old);
    FlushInstructionCache(GetCurrentProcess(), target, copylen);
    return tramp;
}

// ===================== PUENTE CON LA VM DE LUA 5.1 =====================
// RVAs de la API de Lua medidos por CrabeLoader/Lucas (game_profile.cpp,
// perfil di3-gold-steam-1.0) y verificados contra nuestro Ghidra. Son RVA
// (offset desde base), igual que el resto de direcciones de codigo del mod.
// DISENO: lua_pcall es el punto CORRECTO (se llama sin parar en gameplay, en el
// estado bueno, top-level). Pero la materializacion es delicada e
// intermitentemente inestable por si sola, asi que el hook de pcall se instala
// PEREZOSAMENTE (al 1er L3+R3, ya materializado) para no estar activo durante
// ella. loadbuffer se llama DIRECTO (sin hook) para compilar el chunk.
typedef int  (__cdecl *lua_pcall_t)(void* L, int nargs, int nres, int errfunc);
typedef int  (__cdecl *luaL_loadbuffer_t)(void* L, const char* buff, size_t sz, const char* name);
typedef const char* (__cdecl *lua_tolstring_t)(void* L, int idx, size_t* len);
typedef int  (__cdecl *lua_gettop_t)(void* L);
typedef void (__cdecl *lua_settop_t)(void* L, int idx);

#define RVA_LUAL_LOADBUFFER 0xF0EDE0
#define RVA_LUA_PCALL       0xF0DF60
#define RVA_LUA_TOLSTRING   0xF0D5A0
#define RVA_LUA_GETTOP      0xF0D0E0
#define RVA_LUA_SETTOP      0xF0D0F0

static luaL_loadbuffer_t p_loadbuffer = 0;   // directo (loadbuffer real, sin hook)
static lua_tolstring_t   p_tolstring  = 0;
static lua_gettop_t      p_gettop     = 0;
static lua_settop_t      p_settop     = 0;
void* g_tramp_pcall = 0;                      // trampolin del hook de pcall (pcall real)

static void* volatile g_L = 0;           // lua_State de gameplay (capturado en pcall)
static volatile int g_lua_pending = 0;   // 1 = ejecutar g_lua_chunk (trigger L3+R3 de prueba)
static char g_lua_chunk[8192];           // chunk del trigger de prueba (fichero)
static char g_sys_chunk[2560];           // chunks internos del mod (setup / ciclo)
static char g_lua_ret[64];               // ultimo valor devuelto por un chunk (string)
static int  g_in_tick = 0;               // guard anti-reentrada (mismo hilo)
static int  g_pcall_hooked = 0;
static int  g_setup_done = 0;            // COOP_NEXT/COOP_FIX definidos + inicial validado
static volatile int g_cycle_req = 0;     // 1 = procesar cambio de ciclo (RB/LB)
static volatile int g_cycle_dir = 1;     // +1 siguiente, -1 anterior

// Ejecuta un chunk Lua en el estado LS. loadbuffer DIRECTO + trampolin de pcall.
// Guarda el valor devuelto (como string) en g_lua_ret.
static void run_lua_chunk(void* LS, const char* chunk){
    g_lua_ret[0] = 0;
    if(!p_loadbuffer || !g_tramp_pcall || !LS || !chunk) return;
    lua_pcall_t pcall = (lua_pcall_t)g_tramp_pcall;
    int saved = p_gettop ? p_gettop(LS) : 0;
    int st = p_loadbuffer(LS, chunk, (size_t)lstrlenA(chunk), "=coop");
    if(st != 0){
        const char* e = p_tolstring ? p_tolstring(LS, -1, 0) : 0;
        L("[lua] compile err %d: %s", st, e ? e : "?");
        if(p_settop) p_settop(LS, saved);
        return;
    }
    st = pcall(LS, 0, -1, 0);   // -1 = LUA_MULTRET
    if(st != 0){
        const char* e = p_tolstring ? p_tolstring(LS, -1, 0) : 0;
        L("[lua] run err %d: %s", st, e ? e : "?");
    } else if(p_gettop && p_tolstring && p_gettop(LS) > saved){
        const char* r = p_tolstring(LS, -1, 0);
        if(r) lstrcpynA(g_lua_ret, r, sizeof(g_lua_ret));
        L("[lua] chunk OK -> %s", r ? r : "(no-string)");
    } else {
        L("[lua] chunk OK (%d bytes)", lstrlenA(chunk));
    }
    if(p_settop) p_settop(LS, saved);
}

// Construye el chunk de setup: tabla de skus (decimal) + funciones de validez.
// COOP_NEXT(i,d): siguiente indice VALIDO desde i en direccion d (con wrap), 0 si ninguno.
// COOP_FIX(i): i si valido, si no el siguiente valido (para corregir el inicial).
static void build_setup_chunk(void){
    char* p = g_sys_chunk;
    p += sprintf(p, "COOP_SKUS={");
    for(int i=0;i<g_ncyc;i++) p += sprintf(p, "%s%u", i?",":"", (unsigned)g_sku[i]);
    p += sprintf(p,
        "} function COOP_NEXT(i,d) local n=#COOP_SKUS for k=1,n do i=i+d "
        "if i<1 then i=n elseif i>n then i=1 end "
        "if Player_IsCharacterValid(COOP_SKUS[i]) then return i end end return 0 end "
        "function COOP_FIX(i) if Player_IsCharacterValid(COOP_SKUS[i]) then return i else return COOP_NEXT(i,1) end end");
}

// Aplica el personaje del indice idx (0-based) a P2 (re-materializa).
static void apply_cycle_index(int idx){
    if(idx < 0 || idx >= g_ncyc || !g_item[idx]) return;
    g_cyc_idx       = idx;
    g_p2_sku        = g_sku[idx];
    g_p2_item       = g_item[idx];
    g_cycle_pending = 1;        // on_e01890 re-materializa a P2
    L("[cycle] P2 -> %s (0x%x)", g_name[idx], g_sku[idx]);
}

// Handler del hook de pcall (hilo de la VM, top-level). Sin I/O en passthrough.
void on_pcall(void* LS){
    if(!g_L) g_L = LS;
    if(LS != g_L || g_in_tick) return;
    // 1) setup (una vez): define COOP_* y valida/corrige el personaje inicial de P2
    if(!g_setup_done){
        g_in_tick = 1;
        build_setup_chunk();
        run_lua_chunk(LS, g_sys_chunk);
        sprintf(g_sys_chunk, "return COOP_FIX(%d)", g_cyc_idx + 1);
        run_lua_chunk(LS, g_sys_chunk);
        int ni = (int)strtoul(g_lua_ret, 0, 10);
        if(ni >= 1 && ni <= g_ncyc && (ni-1) != g_cyc_idx) apply_cycle_index(ni-1);
        g_setup_done = 1;
        g_in_tick = 0;
        return;
    }
    // 2) peticion de ciclo (RB/LB): siguiente VALIDO en la direccion y aplicar
    if(g_cycle_req){
        g_in_tick = 1;
        sprintf(g_sys_chunk, "return COOP_NEXT(%d,%d)", g_cyc_idx + 1, g_cycle_dir);
        run_lua_chunk(LS, g_sys_chunk);
        int ni = (int)strtoul(g_lua_ret, 0, 10);
        if(ni >= 1 && ni <= g_ncyc) apply_cycle_index(ni-1);
        else L("[cycle] sin personaje valido en este mundo");
        g_cycle_req = 0;
        g_in_tick = 0;
        return;
    }
    // 3) trigger de prueba L3+R3 (chunk de fichero)
    if(g_lua_pending){
        g_in_tick = 1; g_lua_pending = 0;
        run_lua_chunk(LS, g_lua_chunk);
        g_in_tick = 0;
    }
}
// Stub naked (patron probado). L = [esp+4] original -> tras pushal+pushfl en [esp+40].
__attribute__((naked)) void stub_pcall(void){
    __asm__(
        "pushal\n\t"
        "pushfl\n\t"
        "movl 40(%esp), %eax\n\t"
        "pushl %eax\n\t"
        "call _on_pcall\n\t"
        "addl $4, %esp\n\t"
        "popfl\n\t"
        "popal\n\t"
        "jmp *_g_tramp_pcall\n\t"
    );
}

// Resuelve la API de Lua en directo (loadbuffer/tolstring/gettop/settop). Sin hooks.
static int g_lua_bridge_done = 0;
static void install_lua_bridge(void* base){
    if(g_lua_bridge_done) return;
    p_loadbuffer = (luaL_loadbuffer_t)((BYTE*)base + RVA_LUAL_LOADBUFFER);
    p_tolstring  = (lua_tolstring_t)  ((BYTE*)base + RVA_LUA_TOLSTRING);
    p_gettop     = (lua_gettop_t)     ((BYTE*)base + RVA_LUA_GETTOP);
    p_settop     = (lua_settop_t)     ((BYTE*)base + RVA_LUA_SETTOP);
    g_lua_bridge_done = 1;
    L("[lua] API resuelta: loadbuffer=%p", p_loadbuffer);
}

// Instala el hook de pcall PEREZOSAMENTE (tras materializar, al 1er trigger).
static void ensure_pcall_hook(void){
    if(g_pcall_hooked) return;
    void* base = game_base();
    install_hook((BYTE*)base + RVA_LUA_PCALL, (void*)stub_pcall, 7, &g_tramp_pcall);
    g_pcall_hooked = 1;
    L("[lua] pcall hookeado (tramp=%p)", g_tramp_pcall);
}

// Lee coop_lua.txt a g_lua_chunk y lo encola. Instala el hook de pcall si falta.
static void queue_lua_from_file(void){
    ensure_pcall_hook();
    char path[MAX_PATH]; lstrcpynA(path, g_log, MAX_PATH);
    char* p = strrchr(path, '\\'); if(p) strcpy(p+1, "coop_lua.txt"); else strcpy(path, "coop_lua.txt");
    FILE* f = fopen(path, "rb");
    if(!f){ L("[lua] trigger: no abro coop_lua.txt"); return; }
    size_t n = fread(g_lua_chunk, 1, sizeof(g_lua_chunk)-1, f); g_lua_chunk[n] = 0; fclose(f);
    L("[lua] trigger L3+R3: %u bytes encolados", (unsigned)n);
    if(n > 0) g_lua_pending = 1;   // el hook de pcall capta g_L y lo ejecuta
}
// ======================================================================

// ---- materializacion (corre dentro de e01890, mgr=ecx) ----
static int g_frames = 0, g_newHandle = 0, g_joinMsg = 0;
void on_e01890(void* mgr){
    if(!g_active || !mgr) return;
    // CAMBIO DE PERSONAJE: re-materializar el cuerpo de P2 con el nuevo sku
    if(g_cycle_pending){
        g_cycle_pending = 0;
        g_frames = 0; g_newHandle = 0; g_joinMsg = 0;
        *(DWORD*)((BYTE*)mgr + 0x64) = 0;      // borrar handle -> FASE1 re-fuerza el spawn
        *((BYTE*)mgr + 0x845) = 0;             // des-congelar
        g_pending_item = g_p2_item;            // tras re-materializar, cargar su modelo
        L("[coop] re-materializando P2 (nuevo personaje sku 0x%x)...", g_p2_sku);
    }
    g_frames++;
    void* base = game_base();
    *(DWORD*)((BYTE*)base + 0x1E0191C) = 1;               // introFlag
    void* g = *(void**)((BYTE*)base + 0x1E5F540);          // gCountPtr -> g
    if(g){ if(*(DWORD*)((BYTE*)g + 0x94) < 2) *(DWORD*)((BYTE*)g + 0x94) = 2; }
    if(g_newHandle == 0){ DWORD hx = *(DWORD*)((BYTE*)mgr + 0x64); if(hx > 0x100000 && hx != 0xffffffff) g_newHandle = hx; }
    if(g_newHandle == 0 && g_frames < 45){
        void* pA = *(void**)((BYTE*)mgr + 0xC);
        void* pB = *(void**)((BYTE*)mgr + 0x8);
        if(pA){ *(DWORD*)((BYTE*)pA+0x10)=g_p2_sku; *(DWORD*)((BYTE*)pA+0x58)=POSX; *(DWORD*)((BYTE*)pA+0x5C)=0; }
        if(pB){ *(DWORD*)((BYTE*)pB+0x10)=0; *(DWORD*)((BYTE*)pB+0x58)=0; *(DWORD*)((BYTE*)pB+0x5C)=0; }
        *((BYTE*)mgr+0x845)=0; *((BYTE*)mgr+0x880)=0; *((BYTE*)mgr+0x88c)=0;
        *((BYTE*)mgr+0x84b)=0; *((BYTE*)mgr+0x84c)=0;
        *((BYTE*)mgr+0x867)=1; *((BYTE*)mgr+0x83a)=1;
        if(*(int*)((BYTE*)mgr+0xcc) == -1 && g){
            void* ctxArr = *(void**)((BYTE*)g + 0x108);
            if(ctxArr){ void* ctx1 = (BYTE*)ctxArr + 0x50;
                *(DWORD*)((BYTE*)ctx1+0x10)=1; *(DWORD*)((BYTE*)ctx1+0x48)=1;
                *((BYTE*)ctx1+0x20) = *((BYTE*)ctxArr+0x20);
                *(DWORD*)((BYTE*)mgr+0xcc)=1;
            }
        }
    } else {
        *((BYTE*)mgr+0x845)=1; *((BYTE*)mgr+0x83a)=0;   // CONGELAR (cuerpo solido)
        if(!g_joinMsg){ g_joinMsg=1; L("[coop] CONGELADO (cuerpo solido). frames=%d", g_frames); }
        // aplicar/cambiar el personaje de P2 cuando hay uno pendiente (inicial o cambiador)
        if(g_pending_item){
            void* it = g_pending_item; g_pending_item = 0;
            void* self = *(void**)((BYTE*)base + 0x1E1CEB8);   // *(DAT_0221ceb8)
            if(mem_ok(self, 0x40, 0)){
                applychar_t fn = (applychar_t)((BYTE*)base + 0x773060); // FUN_00b73060
                fn(self, 1, it, 1);   // playerId=1 (P2), force=1
                L("[coop] applyChar P2 -> item=%p", it);
            } else L("[coop] applyChar: self no valido");
        }
    }
}

// ---- solidificar avatar slot 1 (dentro de 9e9dc0; args en pila) ----
void on_solidify(void* esp){
    DWORD slot = *(DWORD*)((BYTE*)esp + 4);
    void* av   = *(void**)((BYTE*)esp + 8);
    // limpiar el bit "fantasma" para P2 (slot 1) y tambien P1 (slot 0): al
    // re-materializar P2 en un cambio de personaje, a P1 se le quedaba el bit.
    if((slot == 0 || slot == 1) && av){ BYTE f = *((BYTE*)av + 0x39); if(f & 2) *((BYTE*)av + 0x39) = f & 0xFD; }
}

__attribute__((naked)) void stub_e01890(void){
    __asm__(
        "pushal\n\t"
        "pushfl\n\t"
        "pushl %ecx\n\t"
        "call _on_e01890\n\t"
        "addl $4, %esp\n\t"
        "popfl\n\t"
        "popal\n\t"
        "jmp *_g_tramp_e01890\n\t"
    );
}
__attribute__((naked)) void stub_solidify(void){
    __asm__(
        "pushal\n\t"
        "pushfl\n\t"
        "leal 36(%esp), %eax\n\t"
        "pushl %eax\n\t"
        "call _on_solidify\n\t"
        "addl $4, %esp\n\t"
        "popfl\n\t"
        "popal\n\t"
        "jmp *_g_tramp_solidify\n\t"
    );
}

static void install_hooks(void* base){
    if(g_hooks_done) return;
    install_hook((BYTE*)base + 0xA01890, (void*)stub_e01890, 6, &g_tramp_e01890);
    install_hook((BYTE*)base + 0x9E9DC0, (void*)stub_solidify, 7, &g_tramp_solidify);
    g_hooks_done = 1;
    L("[coop] hooks instalados: e01890=%p solidify=%p", g_tramp_e01890, g_tramp_solidify);
}

// comprobar que [p, p+n) es memoria commit legible (write=1 => escribible)
static int mem_ok(void* p, SIZE_T n, int write){
    MEMORY_BASIC_INFORMATION mbi;
    if(!p) return 0;
    if(VirtualQuery(p, &mbi, sizeof(mbi)) != sizeof(mbi)) return 0;
    if(mbi.State != MEM_COMMIT) return 0;
    if(mbi.Protect & (PAGE_GUARD|PAGE_NOACCESS)) return 0;
    DWORD pr = mbi.Protect & 0xFF;
    int rd = (pr==PAGE_READONLY||pr==PAGE_READWRITE||pr==PAGE_WRITECOPY||
              pr==PAGE_EXECUTE_READ||pr==PAGE_EXECUTE_READWRITE||pr==PAGE_EXECUTE_WRITECOPY);
    int wr = (pr==PAGE_READWRITE||pr==PAGE_WRITECOPY||
              pr==PAGE_EXECUTE_READWRITE||pr==PAGE_EXECUTE_WRITECOPY);
    if((BYTE*)p + n > (BYTE*)mbi.BaseAddress + mbi.RegionSize) return 0;
    return write ? wr : rd;
}

static void run_coop(void){
    if(g_coop_done) return;
    void* base = game_base();
    L("[coop] base=%p", base);

    // OJO: las direcciones de CODIGO ya son RVA (offset desde base), NO se les resta 0x400000.
    // Solo las vtables (find_gameloop) son VA de Ghidra.
    void* pOperand = (BYTE*)base + (0x69E3CF + 2);
    if(!mem_ok(pOperand, 4, 0)){ L("[coop] operando @%p no legible", pOperand); return; }
    DWORD opAddr = *(DWORD*)pOperand;
    L("[coop] opAddr(global)=%08x", opAddr);

    if(!mem_ok((void*)opAddr, 4, 0)){ L("[coop] global @%08x no legible (no estas en partida?)", opAddr); return; }
    void* gamePlayers = *(void**)opAddr;
    L("[coop] gamePlayers=%p", gamePlayers);
    if(!mem_ok(gamePlayers, 0x100, 1)){ L("[coop] gamePlayers no escribible -> entra a una Toy Box y reintenta"); return; }

    *((BYTE*)gamePlayers + 0x98) = 1;
    L("[coop] +0x98=1 OK, buscando gameLoop...");

    void* gameLoop = find_gameloop(base);
    if(!gameLoop){ L("[coop] gameLoop NO encontrado (reintenta con Start)"); return; }
    L("[coop] gameLoop=%p -> DROP-IN", gameLoop);

    read_p2_sku();                       // personaje de P2 desde coop_p2.txt
    install_hooks(base);                 // hooks activos ANTES del drop-in

    dropin_t dropInFn = (dropin_t)((BYTE*)base + 0x69B020);  // RVA (no restar 0x400000)
    *((BYTE*)gamePlayers + 0x98) = 1;
    dropInFn(gameLoop, 1);
    g_coop_done = 1;
    g_active = 1;                         // e01890 empieza a materializar a P2
    L("[coop] drop-in llamado + materializacion ON. P2 solido en ~1s.");
    // descubrir TODOS los personajes cargados (una pasada) + resolver el inicial
    scan_characters();
    g_cyc_idx = 0;
    for(int i=0;i<g_ncyc;i++) if(g_sku[i]==g_p2_sku){ g_cyc_idx=i; break; }
    g_p2_item = (g_cyc_idx>=0 && g_cyc_idx<g_ncyc && g_item[g_cyc_idx]) ? g_item[g_cyc_idx]
                                                                       : resolve_item_ptr(g_p2_sku);
    g_pending_item = g_p2_item;    // aplicar el personaje inicial una vez
    L("[coop] item inicial de P2 (sku 0x%x) = %p", g_p2_sku, g_p2_item);
}
// =========================================================================

typedef DWORD (WINAPI *XInputGetState_t)(DWORD, void*);
static XInputGetState_t pXI = NULL;

static void load_xinput(void){
    const char* dlls[] = {"xinput1_4.dll","xinput1_3.dll","xinput9_1_0.dll","xinput1_2.dll","xinput1_1.dll"};
    for(int i=0;i<5;i++){
        HMODULE m = LoadLibraryA(dlls[i]);
        if(m){ pXI = (XInputGetState_t)GetProcAddress(m, "XInputGetState");
               if(pXI){ L("[xinput] %s", dlls[i]); return; } }
    }
    L("[xinput] NO encontrado");
}

static void coop_trigger(void){
    L("[coop] START en mando 2 -> lanzando secuencia co-op");
    run_coop();
}

static DWORD WINAPI worker(LPVOID unused){
    (void)unused;
    install_lua_bridge(game_base());   // resolver API de Lua (sin hooks)
    Sleep(1500);
    L("=== DI3 co-op mod cargado (proxy bink2w32) ===");
    load_xinput();
    BYTE prev[4] = {0,0,0,0};
    BYTE prevRB[4] = {0,0,0,0};
    BYTE prevLB[4] = {0,0,0,0};
    BYTE prevRun[4] = {0,0,0,0};
    int active_ticks = 0;
    for(;;){
        // tras materializar (~2s), instalar el hook de pcall: valida el personaje inicial
        if(g_active){ if(active_ticks < 1000000) active_ticks++; if(active_ticks == 80) ensure_pcall_hook(); }
        if(pXI){
            for(DWORD pad=0; pad<4; pad++){
                BYTE st[16];
                if(pXI(pad, st) == ERROR_SUCCESS){
                    WORD b = *(WORD*)(st+4);
                    BYTE now = (b & XI_START) ? 1 : 0;
                    if(now && !prev[pad]){
                        L("[input] START en pad %lu", pad);
                        if(pad == 1) coop_trigger();
                    }
                    prev[pad] = now;
                    // CICLADOR P2 (pad 1): RB=siguiente, LB=anterior. Salta invalidos (via Lua).
                    if(pad == 1 && g_active){
                        BYTE rb = (b & 0x0200) ? 1 : 0;   // RIGHT_SHOULDER
                        BYTE lb = (b & 0x0100) ? 1 : 0;   // LEFT_SHOULDER
                        if(rb && !prevRB[pad] && !g_cycle_req && !g_cycle_pending){ ensure_pcall_hook(); g_cycle_dir =  1; g_cycle_req = 1; }
                        if(lb && !prevLB[pad] && !g_cycle_req && !g_cycle_pending){ ensure_pcall_hook(); g_cycle_dir = -1; g_cycle_req = 1; }
                        prevRB[pad] = rb; prevLB[pad] = lb;
                    }
                    // PRUEBA (dev): L3+R3 (clic de ambos sticks) ejecuta coop_lua.txt
                    BYTE run = ((b & 0x00C0) == 0x00C0) ? 1 : 0;   // LEFT_THUMB|RIGHT_THUMB
                    if(run && !prevRun[pad] && pad == 1){ queue_lua_from_file(); }
                    prevRun[pad] = run;
                }
            }
        }
        Sleep(25);
    }
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID r){
    (void)r;
    if(reason == DLL_PROCESS_ATTACH){
        g_self = h;
        GetModuleFileNameA(h, g_log, MAX_PATH);
        char* p = strrchr(g_log, '\\');
        if(p) strcpy(p+1, "di3_coop.log"); else strcpy(g_log, "di3_coop.log");
        DeleteFileA(g_log);
        DisableThreadLibraryCalls(h);
        CreateThread(NULL, 0, worker, NULL, 0, NULL);
    }
    return TRUE;
}
