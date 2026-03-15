package com.v3.ang.ui

import android.os.Bundle
import com.v3.ang.R
import com.v3.ang.handler.V2RayServiceManager

class ScSwitchActivity : BaseActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        moveTaskToBack(true)

        setContentView(R.layout.activity_none)

        if (V2RayServiceManager.isRunning()) {
            V2RayServiceManager.stopVService(this)
        } else {
            V2RayServiceManager.startVServiceFromToggle(this)
        }
        finish()
    }
}
