package com.maze.security.ui.navigation

import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import com.maze.security.AppContainer
import com.maze.security.ui.SessionViewModel
import com.maze.security.ui.screens.config.ConfigScreen
import com.maze.security.ui.screens.consent.ConsentScreen
import com.maze.security.ui.screens.dashboard.DashboardScreen
import com.maze.security.ui.screens.report.ReportScreen
import com.maze.security.ui.screens.settings.SettingsScreen
import com.maze.security.ui.screens.target.TargetScreen
import com.maze.security.ui.screens.terminal.TerminalScreen
import com.maze.security.ui.screens.wordlist.WordlistScreen

@Composable
fun MazeNavHost(container: AppContainer, session: SessionViewModel) {
    val navController = rememberNavController()
    val consentAccepted by container.settings.consentAccepted.collectAsState(initial = null)

    // Wait until we know the consent state before choosing a start destination.
    // The app opens straight onto the tool list; the target is asked for AFTER a tool is picked.
    val start = when (consentAccepted) {
        null -> null
        true -> Routes.DASHBOARD
        false -> Routes.CONSENT
    } ?: return

    NavHost(navController = navController, startDestination = start) {
        composable(Routes.CONSENT) {
            ConsentScreen(
                container = container,
                onAccepted = {
                    navController.navigate(Routes.DASHBOARD) {
                        popUpTo(Routes.CONSENT) { inclusive = true }
                    }
                }
            )
        }
        composable(Routes.DASHBOARD) {
            DashboardScreen(
                container = container,
                session = session,
                onToolSelected = { navController.navigate(Routes.TARGET) },
                onOpenSettings = { navController.navigate(Routes.SETTINGS) },
                onOpenWordlists = { navController.navigate(Routes.WORDLISTS) }
            )
        }
        composable(Routes.TARGET) {
            TargetScreen(
                container = container,
                session = session,
                onContinue = { navController.navigate(Routes.CONFIG) },
                onBack = { navController.popBackStack() }
            )
        }
        composable(Routes.CONFIG) {
            ConfigScreen(
                container = container,
                session = session,
                onRun = { navController.navigate(Routes.TERMINAL) },
                onBack = { navController.popBackStack() },
                onOpenWordlists = { navController.navigate(Routes.WORDLISTS) }
            )
        }
        composable(Routes.TERMINAL) {
            TerminalScreen(
                session = session,
                onViewReport = { navController.navigate(Routes.REPORT) },
                onBack = { navController.popBackStack() }
            )
        }
        composable(Routes.REPORT) {
            ReportScreen(
                session = session,
                onBack = { navController.popBackStack() },
                onHome = {
                    navController.popBackStack(Routes.DASHBOARD, inclusive = false)
                }
            )
        }
        composable(Routes.WORDLISTS) {
            WordlistScreen(
                container = container,
                onBack = { navController.popBackStack() },
                onOpenWordlist = { path ->
                    val arg = android.util.Base64.encodeToString(
                        path.toByteArray(),
                        android.util.Base64.URL_SAFE or android.util.Base64.NO_WRAP or android.util.Base64.NO_PADDING
                    )
                    navController.navigate("wordlist_view/$arg")
                }
            )
        }
        composable(Routes.WORDLIST_VIEW) { backStackEntry ->
            val arg = backStackEntry.arguments?.getString("arg") ?: ""
            val path = runCatching {
                String(android.util.Base64.decode(arg, android.util.Base64.URL_SAFE or android.util.Base64.NO_WRAP or android.util.Base64.NO_PADDING))
            }.getOrDefault("")
            com.maze.security.ui.screens.wordlist.WordlistViewerScreen(
                container = container,
                path = path,
                onBack = { navController.popBackStack() }
            )
        }
        composable(Routes.SETTINGS) {
            SettingsScreen(
                container = container,
                onBack = { navController.popBackStack() }
            )
        }
    }
}
