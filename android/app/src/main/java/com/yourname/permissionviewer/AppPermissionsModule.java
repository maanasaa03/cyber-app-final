package com.yourname.permissionviewer;

import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.Manifest;

import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.WritableArray;
import com.facebook.react.bridge.WritableMap;
import com.facebook.react.bridge.Arguments;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class AppPermissionsModule extends ReactContextBaseJavaModule {

    public AppPermissionsModule(ReactApplicationContext reactContext) {
        super(reactContext);
    }

    @Override
    public String getName() {
        return "AppPermissions";
    }

    @ReactMethod
    public void getInstalledAppsWithPermissions(Promise promise) {
        List<Map<String, Object>> appsWithPermissions = new ArrayList<>();
        PackageManager pm = getReactApplicationContext().getPackageManager();
        List<ApplicationInfo> packages = pm.getInstalledApplications(PackageManager.GET_META_DATA);

        // Define sensitive permissions of interest
        List<String> sensitivePermissions = Arrays.asList(
                Manifest.permission.CAMERA,
                Manifest.permission.ACCESS_FINE_LOCATION,
                Manifest.permission.ACCESS_COARSE_LOCATION,
                Manifest.permission.RECORD_AUDIO
                // Add other sensitive permissions as needed
        );

        for (ApplicationInfo appInfo : packages) {
            Map<String, Object> appData = new HashMap<>();
            List<String> appPermissions = new ArrayList<>();

            try {
                PackageInfo packageInfo = pm.getPackageInfo(appInfo.packageName, PackageManager.GET_PERMISSIONS);
                if (packageInfo.requestedPermissions != null) {
                    for (String permission : packageInfo.requestedPermissions) {
                        if (sensitivePermissions.contains(permission)) {
                            appPermissions.add(permission);
                        }
                    }
                }
                if (!appPermissions.isEmpty()) { // Only add apps with sensitive permissions
                    appData.put("appName", pm.getApplicationLabel(appInfo).toString());
                    appData.put("packageName", appInfo.packageName);
                    appData.put("permissions", appPermissions);
                    appsWithPermissions.add(appData);
                }
            } catch (PackageManager.NameNotFoundException e) {
                e.printStackTrace();
            }
        }
        promise.resolve(Arguments.makeNativeArray(appsWithPermissions));
    }
}


