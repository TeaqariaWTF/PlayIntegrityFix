#include "zygisk.hpp"
#include "dobby.h"
#include <unistd.h>
#include <android/log.h>
#include <sys/system_properties.h>
#include <sys/socket.h>
#include <filesystem>

#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, "SNFix/Zygisk", __VA_ARGS__)

typedef void (*T_Callback)(void *, const char *, const char *, uint32_t);

static void (*o_hook)(const prop_info *, T_Callback, void *);

static T_Callback o_callback;

static void
handle_system_property(void *cookie, const char *name, const char *value, uint32_t serial) {
    if (std::string_view(name).compare("ro.product.first_api_level") == 0) {
        LOGI("Set first_api_level to 33, original value: %s", value);
        value = "33";
    }
    o_callback(cookie, name, value, serial);
}

static void my_hook(const prop_info *pi, T_Callback callback, void *cookie) {
    o_callback = callback;
    o_hook(pi, handle_system_property, cookie);
}

using namespace zygisk;

class PlayIntegrityFix : public ModuleBase {
public:
    void onLoad(Api *api, JNIEnv *env) override {
        this->api = api;
        this->env = env;
    }

    void preAppSpecialize(AppSpecializeArgs *args) override {
        auto rawProcess = env->GetStringUTFChars(args->nice_name, nullptr);
        std::string process(rawProcess);
        env->ReleaseStringUTFChars(args->nice_name, rawProcess);

        if (!process.starts_with("com.google.android.gms")) {
            process.clear();
            process.shrink_to_fit();
            api->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
            return;
        }

        api->setOption(zygisk::FORCE_DENYLIST_UNMOUNT);

        if (process == "com.google.android.gms.unstable") {
            auto rawAppDir = env->GetStringUTFChars(args->app_data_dir, nullptr);
            appDir = rawAppDir;
            env->ReleaseStringUTFChars(args->app_data_dir, rawAppDir);

            int fd = api->connectCompanion();
            int strSize = (int) appDir.size();
            send(fd, &strSize, sizeof(strSize), 0);
            send(fd, appDir.data(), appDir.size(), 0);
            bool correct;
            recv(fd, &correct, sizeof(correct), 0);
            close(fd);

            if (!correct) {
                appDir.clear();
                appDir.shrink_to_fit();
                api->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
            }
        }

        process.clear();
        process.shrink_to_fit();
    }

    void postAppSpecialize(const AppSpecializeArgs *args) override {
        if (appDir.empty()) return;

        LOGI("hooking");
        void *handle = DobbySymbolResolver(nullptr, "__system_property_read_callback");
        if (handle == nullptr) {
            LOGI("Error, can't get __system_property_read_callback handle");
            appDir.clear();
            appDir.shrink_to_fit();
            return;
        }
        LOGI("Get __system_property_read_callback at %p", handle);
        DobbyHook(handle, (dobby_dummy_func_t) my_hook, (dobby_dummy_func_t *) &o_hook);

        LOGI("get system classloader");
        auto clClass = env->FindClass("java/lang/ClassLoader");
        auto getSystemClassLoader = env->GetStaticMethodID(clClass, "getSystemClassLoader",
                                                           "()Ljava/lang/ClassLoader;");
        auto systemClassLoader = env->CallStaticObjectMethod(clClass, getSystemClassLoader);

        auto dexFile = env->NewStringUTF(std::string(appDir + "/SNFix.dex").c_str());

        LOGI("create PathClassLoader");
        auto dexClClass = env->FindClass("dalvik/system/PathClassLoader");
        auto dexClInit = env->GetMethodID(dexClClass, "<init>",
                                          "(Ljava/lang/String;Ljava/lang/ClassLoader;)V");
        auto dexCl = env->NewObject(dexClClass, dexClInit, dexFile, systemClassLoader);

        LOGI("load class");
        auto loadClass = env->GetMethodID(clClass, "loadClass",
                                          "(Ljava/lang/String;)Ljava/lang/Class;");
        auto entryClassName = env->NewStringUTF("dev.kdrag0n.safetynetfix.EntryPoint");
        auto entryClassObj = env->CallObjectMethod(dexCl, loadClass, entryClassName);

        LOGI("call init");
        auto entryClass = (jclass) entryClassObj;
        auto entryInit = env->GetStaticMethodID(entryClass, "init", "()V");
        env->CallStaticVoidMethod(entryClass, entryInit);

        LOGI("cleaning");
        appDir.clear();
        appDir.shrink_to_fit();
        env->DeleteLocalRef(clClass);
        env->DeleteLocalRef(systemClassLoader);
        env->DeleteLocalRef(dexFile);
        env->DeleteLocalRef(dexClClass);
        env->DeleteLocalRef(dexCl);
        env->DeleteLocalRef(entryClassName);
        env->DeleteLocalRef(entryClassObj);
        env->DeleteLocalRef(entryClass);
    }

    void preServerSpecialize(ServerSpecializeArgs *args) override {
        api->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
    }

private:
    Api *api;
    JNIEnv *env;
    std::string appDir;
};

static void companion(int fd) {
    int strSize;
    recv(fd, &strSize, sizeof(strSize), 0);

    std::string appDir;
    appDir.resize(strSize);

    recv(fd, appDir.data(), appDir.size(), 0);

    LOGI("[ROOT] Received app data dir from socket: %s", appDir.c_str());

    bool correct = std::filesystem::copy_file("/data/adb/SNFix.dex",
                                              appDir + "/SNFix.dex",
                                              std::filesystem::copy_options::overwrite_existing);

    if (correct) {
        std::filesystem::permissions(appDir + "/SNFix.dex",
                                     std::filesystem::perms::group_read |
                                     std::filesystem::perms::owner_read |
                                     std::filesystem::perms::others_read);
    }

    send(fd, &correct, sizeof(correct), 0);
}

REGISTER_ZYGISK_MODULE(PlayIntegrityFix)

REGISTER_ZYGISK_COMPANION(companion)