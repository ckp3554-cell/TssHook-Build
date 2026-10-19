#include <jni.h>
#include <android/log.h>
#include <dlfcn.h>
#include <pthread.h>
#include <unistd.h>
#include <stdint.h>
#include "shadowhook.h"

#define TAG "TssHook"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)

using get_t = int (*)(void*, int*);
using del_t = int (*)(void*);

static get_t og_get1, og_get2, og_get3, og_get4;
static del_t og_del1, og_del3, og_del4;

static int hk_get1(void* d, int* s) { if(s)*s=0; return -1; }
static int hk_get2(void* d, int* s) { if(s)*s=0; return -1; }
static int hk_get3(void* d, int* s) { if(s)*s=0; return -1; }
static int hk_get4(void* d, int* s) { if(s)*s=0; return -1; }
static int hk_del1(void* d) { return 0; }
static int hk_del3(void* d) { return 0; }
static int hk_del4(void* d) { return 0; }

static void hook_one(void* lib, const char* sym, void* stub, void** orig) {
    if (*orig) return;
    void* a = dlsym(lib, sym);
    if (!a) return;
    if (shadowhook_hook_sym_addr(a, stub, orig) == SHADOWHOOK_ERRNO_OK)
        LOGI("hook ok: %s", sym);
}

static void try_hook(const char* name) {
    void* lib = dlopen(name, RTLD_NOW | RTLD_NOLOAD);
    if (!lib) lib = dlopen(name, RTLD_NOW);
    if (!lib) return;
    hook_one(lib, "tss_get_report_data",  (void*)hk_get1, (void**)&og_get1);
    hook_one(lib, "tss_get_report_data2", (void*)hk_get2, (void**)&og_get2);
    hook_one(lib, "tss_get_report_data3", (void*)hk_get3, (void**)&og_get3);
    hook_one(lib, "tss_get_report_data4", (void*)hk_get4, (void**)&og_get4);
    hook_one(lib, "tss_del_report_data",  (void*)hk_del1, (void**)&og_del1);
    hook_one(lib, "tss_del_report_data3", (void*)hk_del3, (void**)&og_del3);
    hook_one(lib, "tss_del_report_data4", (void*)hk_del4, (void**)&og_del4);
}

static void* worker(void*) {
    static const char* libs[] = {"libtersafe2.so", "libtersafe.so", "libtsssdk.so"};
    bool inited = false;
    for (int i = 0; i < 300; ++i) {
        if (!inited) {
            for (auto n : libs)
                if (dlopen(n, RTLD_NOW | RTLD_NOLOAD)) {
                    shadowhook_init(SHADOWHOOK_MODE_UNIQUE, false);
                    inited = true;
                    break;
                }
        }
        if (inited) for (auto n : libs) try_hook(n);
        sleep(1);
    }
    return nullptr;
}

__attribute__((constructor))
static void on_load() {
    pthread_t th;
    if (pthread_create(&th, nullptr, worker, nullptr) == 0) pthread_detach(th);
}
