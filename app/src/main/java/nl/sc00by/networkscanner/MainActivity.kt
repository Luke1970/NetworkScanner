package nl.sc00by.networkscanner

import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import nl.sc00by.networkscanner.ui.ScanScreen

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            val dark = isSystemInDarkTheme()
            val colors = when {
                Build.VERSION.SDK_INT >= Build.VERSION_CODES.S ->
                    if (dark) dynamicDarkColorScheme(LocalContext.current) else dynamicLightColorScheme(LocalContext.current)
                dark -> darkColorScheme()
                else -> lightColorScheme()
            }
            // Buttons, links and progress indicators in black (white in dark mode); the selected
            // segment of the port-scope switch in the logo's yellow.
            val ink = if (dark) Color.White else Color.Black
            val paper = if (dark) Color.Black else Color.White
            val themed = colors.copy(
                primary = ink,
                onPrimary = paper,
                secondaryContainer = Color(0xFFFFD600),
                onSecondaryContainer = Color.Black,
            )
            MaterialTheme(colorScheme = themed) { ScanScreen() }
        }
    }
}
