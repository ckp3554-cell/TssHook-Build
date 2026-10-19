package com.example.tsshook;

import android.app.Application;
import android.content.Context;
import android.os.Build;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.lang.reflect.Method;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

public class MainHook implements IXposedHookLoadPackage {

    private static final String TARGET_PKG = "com.tencent.tmgp.speedmobile";
    private static final String TAG = "[TssHook]";
    private static boolean sLoaded = false;

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lp) {
        if (!TARGET_PKG.equals(lp.packageName)) return;
        XposedBridge.log(TAG + " 命中 " + lp.packageName + " / proc=" + lp.processName);

        XposedHelpers.findAndHookMethod(Application.class, "attach", Context.class,
                new XC_MethodHook() {
                    @Override protected void afterHookedMethod(MethodHookParam p) {
                        Context ctx = (Context) p.args[0];
                        loadNative(ctx);
                        hookTp2Sdk(lp.classLoader);
                        hookRootChecks();
                        spoofBuild();
                    }
                });
    }

    private synchronized void loadNative(Context ctx) {
        if (sLoaded) return;
        sLoaded = true;
        try {
            System.loadLibrary("tsshook");
            XposedBridge.log(TAG + " native 加载成功");
            return;
        } catch (Throwable t) {
            XposedBridge.log(TAG + " 尝试 copy 加载: " + t);
        }

        try {
            String apkPath = MainHook.class.getProtectionDomain().getCodeSource().getLocation().getPath();
            if (apkPath.startsWith("file:")) apkPath = apkPath.substring(5);
            File apk = new File(apkPath);
            
            String abi = Build.SUPPORTED_ABIS[0];
            if (!"arm64-v8a".equals(abi) && !"armeabi-v7a".equals(abi))
                abi = abi.startsWith("arm64") ? "arm64-v8a" : "armeabi-v7a";

            String libName = "libtsshook.so";
            File outDir = new File(ctx.getCodeCacheDir(), "tsshook");
            if (!outDir.exists()) outDir.mkdirs();
            File outLib = new File(outDir, libName);
            if (outLib.exists()) outLib.delete();

            try (ZipFile zip = new ZipFile(apk)) {
                ZipEntry e = zip.getEntry("lib/" + abi + "/" + libName);
                if (e == null) return;
                try (InputStream in = zip.getInputStream(e); FileOutputStream fos = new FileOutputStream(outLib)) {
                    byte[] buf = new byte[8192]; int n;
                    while ((n = in.read(buf)) > 0) fos.write(buf, 0, n);
                }
            }
            System.load(outLib.getAbsolutePath());
            XposedBridge.log(TAG + " native copy 加载成功");
        } catch (Throwable t) {
            XposedBridge.log(TAG + " native 加载彻底失败: " + t);
        }
    }

    private void hookTp2Sdk(ClassLoader cl) {
        String[] candidates = { "com.tencent.tp.TP2Sdk", "com.tencent.gcloud.TP2Sdk", "com.tencent.tmgp.speedmobile.TP2Sdk" };
        Class<?> c = null;
        for (String cn : candidates) {
            c = XposedHelpers.findClassIfExists(cn, cl);
            if (c != null) break;
        }
        if (c == null) return;

        for (String m : new String[]{"getReportData", "getReportData2", "getReportData3", "getReportData4"}) {
            Method mm = null;
            try { mm = c.getDeclaredMethod(m); } catch (Throwable ignored) {}
            if (mm == null) continue;
            XposedBridge.hookMethod(mm, new XC_MethodHook() {
                @Override protected void afterHookedMethod(MethodHookParam p) { p.setResult(new byte[0]); }
            });
        }
        try {
            Method io = c.getDeclaredMethod("ioctl", String.class);
            XposedBridge.hookMethod(io, new XC_MethodHook() {
                @Override protected void afterHookedMethod(MethodHookParam p) { p.setResult(""); }
            });
        } catch (Throwable ignored) {}
    }

    private void hookRootChecks() {
        final String[] blacklist = { "/su", "magisk", "superuser", "xposed", "frida", "substrate", "busybox" };
        try {
            XposedHelpers.findAndHookMethod(File.class, "exists", new XC_MethodHook() {
                @Override protected void beforeHookedMethod(MethodHookParam p) {
                    String path = ((File) p.thisObject).getAbsolutePath().toLowerCase();
                    for (String b : blacklist) if (path.contains(b)) { p.setResult(false); return; }
                }
            });
        } catch (Throwable ignored) {}

        try {
            XposedHelpers.findAndHookMethod(Runtime.class, "exec", String[].class, new XC_MethodHook() {
                @Override protected void beforeHookedMethod(MethodHookParam p) {
                    String[] cmds = (String[]) p.args[0];
                    if (cmds == null) return;
                    String joined = String.join(" ", cmds).toLowerCase();
                    if (joined.contains("su") || joined.contains("which")) p.setResult(null);
                }
            });
        } catch (Throwable ignored) {}
    }

    private void spoofBuild() {
        try {
            XposedHelpers.setStaticObjectField(Build.class, "TAGS", "release-keys");
            XposedHelpers.setStaticObjectField(Build.class, "TYPE", "user");
        } catch (Throwable ignored) {}
    }
                     }
