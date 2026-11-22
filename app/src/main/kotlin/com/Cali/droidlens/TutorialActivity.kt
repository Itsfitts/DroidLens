package com.Cali.droidlens

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.widget.ImageButton
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.google.android.material.button.MaterialButton

class TutorialActivity : AppCompatActivity() {

    private lateinit var btnTutorialBack: ImageButton
    private lateinit var tvTutorialKsuJson: TextView
    private lateinit var btnCopyTutorialKsuJson: MaterialButton
    private lateinit var btnOpenKernelSu: MaterialButton
    private lateinit var btnTutorialGotIt: MaterialButton

    private var profileJsonText = ""

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_tutorial)

        btnTutorialBack = findViewById(R.id.btnTutorialBack)
        tvTutorialKsuJson = findViewById(R.id.tvTutorialKsuJson)
        btnCopyTutorialKsuJson = findViewById(R.id.btnCopyTutorialKsuJson)
        btnOpenKernelSu = findViewById(R.id.btnOpenKernelSu)
        btnTutorialGotIt = findViewById(R.id.btnTutorialGotIt)

        loadProfileJson()

        btnTutorialBack.setOnClickListener { finish() }
        btnTutorialGotIt.setOnClickListener { finish() }

        btnCopyTutorialKsuJson.setOnClickListener {
            if (profileJsonText.isNotBlank()) {
                val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                val clip = ClipData.newPlainText("DroidLens KernelSU Profile", profileJsonText)
                clipboard.setPrimaryClip(clip)
                Toast.makeText(this, "Profile copied! Paste it in KernelSU Manager.", Toast.LENGTH_SHORT).show()
            }
        }

        btnOpenKernelSu.setOnClickListener {
            val ksuPackage = "me.weishu.kernelsu"
            val launchIntent = packageManager.getLaunchIntentForPackage(ksuPackage)
            if (launchIntent != null) {
                startActivity(launchIntent)
            } else {
                Toast.makeText(this, "KernelSU Manager app not found. Please open it manually.", Toast.LENGTH_LONG).show()
            }
        }
    }

    private fun loadProfileJson() {
        profileJsonText = try {
            assets.open("kernelsu_profile.json").bufferedReader().use { it.readText() }
        } catch (_: Throwable) {
            """
[
  {
    "id": "com.Cali.droidlens",
    "name": "DroidLens Security & Kernel Profiler",
    "description": "Least-privilege profile granting process tracing, child execve inspection, and logcat extraction for APK dynamic strace profiling and privilege auditing.",
    "author": "DroidLens",
    "namespace": "GLOBAL",
    "uid": 0,
    "gid": 0,
    "groups": [
      "ROOT",
      "SYSTEM",
      "SHELL"
    ],
    "capabilities": [
      "CAP_SYS_PTRACE",
      "CAP_KILL",
      "CAP_DAC_READ_SEARCH",
      "CAP_SYS_ADMIN"
    ],
    "context": "u:r:ksu:s0",
    "flags": []
  }
]
""".trimIndent()
        }

        tvTutorialKsuJson.text = profileJsonText
    }
}
