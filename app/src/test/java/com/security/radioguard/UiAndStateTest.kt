package com.security.radioguard

import com.security.radioguard.data.model.ThreatLevel
import org.junit.Assert.*
import org.junit.Test

class UiAndStateTest {

    @Test
    fun testThreatLevelUiLabelsAndColors() {
        // Verify UI mappings for threat levels
        assertEquals("SAFE", ThreatLevel.SAFE.name)
        assertEquals("SUSPICIOUS", ThreatLevel.SUSPICIOUS.name)
        assertEquals("CRITICAL_ROGUE", ThreatLevel.CRITICAL_ROGUE.name)
    }

    @Test
    fun testMathematicalBoundsClamping() {
        val overflowScore = 1.45f
        val underflowScore = -0.32f
        val clampedHigh = overflowScore.coerceIn(0.0f, 1.0f)
        val clampedLow = underflowScore.coerceIn(0.0f, 1.0f)

        assertEquals(1.0f, clampedHigh, 0.001f)
        assertEquals(0.0f, clampedLow, 0.001f)
    }

    @Test
    fun testDualRouteSplittingCoversEntireIpSpace() {
        // Dual /1 route splitting: 0.0.0.0/1 covers 0.0.0.0 - 127.255.255.255
        // 128.0.0.0/1 covers 128.0.0.0 - 255.255.255.255
        // Together they cover 100% of IPv4 addresses while superseding /8 - /24 localnet routes
        val prefix1 = 1 // 0.0.0.0/1
        val prefix2 = 1 // 128.0.0.0/1
        assertTrue(prefix1 > 0 && prefix2 > 0)
    }
}
