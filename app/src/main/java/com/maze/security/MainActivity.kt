package com.maze.security

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.lifecycle.viewmodel.compose.viewModel
import com.maze.security.ui.SessionViewModel
import com.maze.security.ui.navigation.MazeNavHost
import com.maze.security.ui.theme.MazeSecurityTheme
import com.maze.security.ui.theme.ThemeMode

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        val container = (application as MazeApp).container
        setContent {
            val session: SessionViewModel = viewModel(factory = SessionViewModel.Factory(container))
            val themeMode by container.settings.themeMode.collectAsState(initial = ThemeMode.OLED)
            MazeSecurityTheme(themeMode = themeMode) {
                MazeNavHost(container = container, session = session)
            }
        }
    }
}
