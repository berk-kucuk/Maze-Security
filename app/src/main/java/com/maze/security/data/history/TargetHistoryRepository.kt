package com.maze.security.data.history

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map

private val Context.historyStore: DataStore<Preferences> by preferencesDataStore(name = "maze_history")

/** Stores recently scanned targets (most-recent first, capped). */
class TargetHistoryRepository(private val context: Context) {

    private val key = stringPreferencesKey("recent_targets")
    private val sep = "␟"

    val recentTargets: Flow<List<String>> = context.historyStore.data.map { prefs ->
        prefs[key]?.split(sep)?.filter { it.isNotBlank() } ?: emptyList()
    }

    suspend fun add(target: String) {
        context.historyStore.edit { prefs ->
            val current = prefs[key]?.split(sep)?.filter { it.isNotBlank() } ?: emptyList()
            val updated = (listOf(target) + current.filter { it != target }).take(12)
            prefs[key] = updated.joinToString(sep)
        }
    }

    suspend fun clear() {
        context.historyStore.edit { it.remove(key) }
    }
}
