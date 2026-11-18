package com.maze.security.domain

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** SEC3: a target must never reach nmap/hydra/medusa as one of their options. */
class TargetValidatorTest {

    @Test
    fun optionLikeTargetsAreRefused() = runBlocking {
        for (bad in listOf("-oN /sdcard/x", "-iL", "--script=evil", " -sS", "a b", "x\ty", "")) {
            assertFalse(bad, TargetValidator.isSafeToolArgument(bad))
            assertNull(bad, TargetValidator.resolve(bad))
        }
    }

    @Test
    fun ordinaryTargetsStillWork() = runBlocking {
        for (good in listOf("192.168.1.10", "10.0.0.0/24", "10.0.0.1-50", "example.com",
                            "fe80::1", "scanme.nmap.org")) {
            assertTrue(good, TargetValidator.isSafeToolArgument(good))
        }
        val t = TargetValidator.resolve("10.0.0.0/24")
        assertNotNull(t)
        assertEquals("10.0.0.0/24", t!!.hostForTools)
        assertEquals("192.168.1.10", TargetValidator.resolve("  192.168.1.10 ")!!.hostForTools)
    }
}
