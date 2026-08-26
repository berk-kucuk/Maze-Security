package com.maze.security.data.prefs

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.intPreferencesKey
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import com.maze.security.ui.theme.ThemeMode
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map

private val Context.dataStore: DataStore<Preferences> by preferencesDataStore(name = "maze_settings")

/** Persists user preferences: theme, consent acknowledgement, and scan defaults. */
class SettingsRepository(private val context: Context) {

    private object Keys {
        val THEME = stringPreferencesKey("theme_mode")
        val CONSENT = booleanPreferencesKey("consent_accepted")
        val DEF_THREADS = intPreferencesKey("default_threads")
        val DEF_TIMEOUT = intPreferencesKey("default_timeout_ms")
    }

    val themeMode: Flow<ThemeMode> = context.dataStore.data.map { prefs ->
        runCatching { ThemeMode.valueOf(prefs[Keys.THEME] ?: ThemeMode.OLED.name) }
            .getOrDefault(ThemeMode.OLED)
    }

    val consentAccepted: Flow<Boolean> = context.dataStore.data.map { it[Keys.CONSENT] ?: false }

    val defaultThreads: Flow<Int> = context.dataStore.data.map { it[Keys.DEF_THREADS] ?: 16 }
    val defaultTimeoutMs: Flow<Int> = context.dataStore.data.map { it[Keys.DEF_TIMEOUT] ?: 4000 }

    suspend fun setThemeMode(mode: ThemeMode) =
        context.dataStore.edit { it[Keys.THEME] = mode.name }.let { }

    suspend fun setConsentAccepted(accepted: Boolean) =
        context.dataStore.edit { it[Keys.CONSENT] = accepted }.let { }

    suspend fun setDefaultThreads(n: Int) =
        context.dataStore.edit { it[Keys.DEF_THREADS] = n }.let { }

    suspend fun setDefaultTimeout(ms: Int) =
        context.dataStore.edit { it[Keys.DEF_TIMEOUT] = ms }.let { }
}
