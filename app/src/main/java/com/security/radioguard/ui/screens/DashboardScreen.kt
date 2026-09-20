package com.security.radioguard.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.GppBad
import androidx.compose.material.icons.filled.GppGood
import androidx.compose.material.icons.filled.GppMaybe
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.security.radioguard.data.model.AnomalyReport
import com.security.radioguard.data.model.ThreatLevel
import com.security.radioguard.ui.theme.*

@Composable
fun DashboardScreen(
    isSentryRunning: Boolean,
    isVpnActive: Boolean,
    report: AnomalyReport?,
    totalVerifiedTowers: Int,
    incidentCount: Int,
    deviceStatus: com.security.radioguard.security.DeviceIntegritySentry.IntegrityStatus,
    onToggleSentry: (Boolean) -> Unit,
    onToggleVpn: (Boolean) -> Unit,
    onBreakTowerLock: () -> Unit,
    onExportIncidents: () -> Unit
) {
    val scrollState = rememberScrollState()

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(CyberDarkBg)
            .padding(16.dp)
            .verticalScroll(scrollState)
    ) {
        // App Header
        Row(
            verticalAlignment = Alignment.CenterVertically,
            modifier = Modifier.fillMaxWidth().padding(bottom = 16.dp)
        ) {
            Icon(
                imageVector = Icons.Default.Shield,
                contentDescription = null,
                tint = CyberCyan,
                modifier = Modifier.size(32.dp)
            )
            Spacer(modifier = Modifier.width(12.dp))
            Column {
                Text(
                    text = "RADIOGUARD",
                    color = Color.White,
                    fontSize = 20.sp,
                    fontWeight = FontWeight.Bold,
                    fontFamily = FontFamily.Monospace
                )
                Text(
                    text = "Zero-Trust Cellular Defense",
                    color = Color.Gray,
                    fontSize = 12.sp
                )
            }
        }

        // Host Device Compromise Alert Banner (if OS/kernel is tampered)
        if (deviceStatus.isCompromised) {
            Card(
                colors = CardDefaults.cardColors(containerColor = Color(0xFF3E0A10)),
                shape = RoundedCornerShape(12.dp),
                modifier = Modifier.fillMaxWidth().padding(bottom = 16.dp)
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text(
                        text = "HOST DEVICE INTEGRITY WARNING",
                        color = ThreatRed,
                        fontWeight = FontWeight.Bold,
                        fontSize = 13.sp
                    )
                    Text(
                        text = "Device appears rooted, running permissive SELinux, or modified. Zero-trust cellular guarantees may be bypassed by kernel-level adversaries.",
                        color = Color.LightGray,
                        fontSize = 11.sp,
                        modifier = Modifier.padding(top = 4.dp)
                    )
                }
            }
        }

        // Threat Status Card
        ThreatGaugeCard(report = report)

        Spacer(modifier = Modifier.height(16.dp))

        // Active Connection Details
        ActiveCellDetailsCard(report = report)

        Spacer(modifier = Modifier.height(16.dp))

        // Forensic Incident Log Card
        ForensicIncidentsCard(incidentCount = incidentCount, onExport = onExportIncidents)

        Spacer(modifier = Modifier.height(16.dp))

        // Quick Defense Controls
        DefenseControlsCard(
            isSentryRunning = isSentryRunning,
            isVpnActive = isVpnActive,
            onToggleSentry = onToggleSentry,
            onToggleVpn = onToggleVpn,
            onBreakTowerLock = onBreakTowerLock
        )

        Spacer(modifier = Modifier.height(16.dp))

        // Database & System Status
        DatabaseStatusCard(totalVerifiedTowers = totalVerifiedTowers)
    }
}

@Composable
fun ThreatGaugeCard(report: AnomalyReport?) {
    val level = report?.threatLevel ?: ThreatLevel.SAFE
    val (statusText, statusColor, icon) = when (level) {
        ThreatLevel.SAFE -> Triple("SECURE: NO ROGUE CELLS", ThreatGreen, Icons.Default.GppGood)
        ThreatLevel.SUSPICIOUS -> Triple("WARNING: UNVERIFIED ANOMALY", ThreatYellow, Icons.Default.GppMaybe)
        ThreatLevel.CRITICAL_ROGUE -> Triple("CRITICAL: ROGUE TOWER TRAPPED", ThreatRed, Icons.Default.GppBad)
    }

    Card(
        colors = CardDefaults.cardColors(containerColor = CyberSurface),
        shape = RoundedCornerShape(12.dp),
        modifier = Modifier
            .fillMaxWidth()
            .border(1.dp, statusColor.copy(alpha = 0.5f), RoundedCornerShape(12.dp))
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Box(
                    modifier = Modifier
                        .size(12.dp)
                        .clip(CircleShape)
                        .background(statusColor)
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    text = statusText,
                    color = statusColor,
                    fontWeight = FontWeight.Bold,
                    fontSize = 14.sp
                )
            }

            Spacer(modifier = Modifier.height(12.dp))

            val riskPercent = ((report?.riskScore ?: 0f) * 100).toInt()
            LinearProgressIndicator(
                progress = { (report?.riskScore ?: 0f).coerceIn(0f, 1f) },
                modifier = Modifier.fillMaxWidth().height(8.dp).clip(RoundedCornerShape(4.dp)),
                color = statusColor,
                trackColor = CyberSurfaceBorder
            )

            Spacer(modifier = Modifier.height(8.dp))

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Text(text = "Anomaly Risk Score", color = Color.Gray, fontSize = 12.sp)
                Text(text = "$riskPercent%", color = Color.White, fontWeight = FontWeight.Bold, fontSize = 12.sp)
            }

            if (!report?.reasons.isNullOrEmpty()) {
                Spacer(modifier = Modifier.height(8.dp))
                HorizontalDivider(color = CyberSurfaceBorder)
                Spacer(modifier = Modifier.height(8.dp))
                Text(text = "Detection Factors:", color = Color.Gray, fontSize = 12.sp, fontWeight = FontWeight.SemiBold)
                report?.reasons?.forEach { reason ->
                    Text(text = "• $reason", color = Color(0xFFFF8A80), fontSize = 11.sp, modifier = Modifier.padding(top = 2.dp))
                }
            }
        }
    }
}

@Composable
fun ActiveCellDetailsCard(report: AnomalyReport?) {
    val obs = report?.observation

    Card(
        colors = CardDefaults.cardColors(containerColor = CyberSurface),
        shape = RoundedCornerShape(12.dp),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text(
                text = "SERVING CELL TELEMETRY",
                color = CyberCyan,
                fontWeight = FontWeight.Bold,
                fontSize = 12.sp,
                fontFamily = FontFamily.Monospace
            )
            Spacer(modifier = Modifier.height(8.dp))

            if (obs != null) {
                CellMetricRow(label = "Radio Generation", value = obs.generation.name)
                CellMetricRow(label = "PLMN (MCC / MNC)", value = "${obs.mcc} / ${obs.mnc}")
                CellMetricRow(label = "Tracking / Location Area", value = obs.areaCode.toString())
                CellMetricRow(label = "Cell ID (CID / ECI)", value = obs.cellId.toString())
                CellMetricRow(label = "Signal Power (RSRP)", value = "${obs.rsrpDbm} dBm")
                CellMetricRow(label = "Neighbor Cells", value = "${obs.neighborCount} detected")
            } else {
                Text(
                    text = "Awaiting radio telemetry from baseband sentry...",
                    color = Color.Gray,
                    fontSize = 13.sp
                )
            }
        }
    }
}

@Composable
fun CellMetricRow(label: String, value: String) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(vertical = 3.dp),
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Text(text = label, color = Color.LightGray, fontSize = 12.sp)
        Text(text = value, color = Color.White, fontWeight = FontWeight.Medium, fontSize = 12.sp, fontFamily = FontFamily.Monospace)
    }
}

@Composable
fun DefenseControlsCard(
    isSentryRunning: Boolean,
    isVpnActive: Boolean,
    onToggleSentry: (Boolean) -> Unit,
    onToggleVpn: (Boolean) -> Unit,
    onBreakTowerLock: () -> Unit
) {
    Card(
        colors = CardDefaults.cardColors(containerColor = CyberSurface),
        shape = RoundedCornerShape(12.dp),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text(
                text = "ACTIVE DEFENSE CONTROLS",
                color = CyberCyan,
                fontWeight = FontWeight.Bold,
                fontSize = 12.sp,
                fontFamily = FontFamily.Monospace
            )
            Spacer(modifier = Modifier.height(12.dp))

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column {
                    Text(text = "Continuous Sentry", color = Color.White, fontWeight = FontWeight.SemiBold)
                    Text(text = "Real-time baseband anomaly monitoring", color = Color.Gray, fontSize = 11.sp)
                }
                Switch(checked = isSentryRunning, onCheckedChange = onToggleSentry)
            }

            HorizontalDivider(color = CyberSurfaceBorder, modifier = Modifier.padding(vertical = 8.dp))

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column {
                    Text(text = "Safe-Routing Kill-Switch", color = Color.White, fontWeight = FontWeight.SemiBold)
                    Text(text = "Encapsulates traffic; blocks 4G aLTEr bit-flipping", color = Color.Gray, fontSize = 11.sp)
                }
                Switch(checked = isVpnActive, onCheckedChange = onToggleVpn)
            }

            Spacer(modifier = Modifier.height(12.dp))

            OutlinedButton(
                onClick = onBreakTowerLock,
                modifier = Modifier.fillMaxWidth(),
                colors = ButtonDefaults.outlinedButtonColors(contentColor = Color(0xFFFFAB40)),
                border = ButtonDefaults.outlinedButtonBorder.copy(brush = androidx.compose.ui.graphics.SolidColor(Color(0xFFFFAB40)))
            ) {
                Text("Pulse Radio / Break Tower Lock (Shizuku)")
            }
        }
    }
}

@Composable
fun DatabaseStatusCard(totalVerifiedTowers: Int) {
    Card(
        colors = CardDefaults.cardColors(containerColor = CyberSurface),
        shape = RoundedCornerShape(12.dp),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text(
                text = "OFFLINE GROUND-TRUTH DATABASE",
                color = CyberCyan,
                fontWeight = FontWeight.Bold,
                fontSize = 12.sp,
                fontFamily = FontFamily.Monospace
            )
            Spacer(modifier = Modifier.height(8.dp))
            Text(
                text = "Verified Macro-Towers: $totalVerifiedTowers",
                color = Color.White,
                fontWeight = FontWeight.Bold,
                fontSize = 14.sp
            )
            Text(
                text = "Regional OpenCelliD / BeaconDB spatial baseline loaded in protected local SQLite.",
                color = Color.Gray,
                fontSize = 11.sp,
                modifier = Modifier.padding(top = 4.dp)
            )
        }
    }
}

@Composable
fun ForensicIncidentsCard(incidentCount: Int, onExport: () -> Unit) {
    Card(
        colors = CardDefaults.cardColors(containerColor = CyberSurface),
        shape = RoundedCornerShape(12.dp),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column {
                    Text(
                        text = "FORENSIC INCIDENT EVIDENCE",
                        color = CyberCyan,
                        fontWeight = FontWeight.Bold,
                        fontSize = 12.sp,
                        fontFamily = FontFamily.Monospace
                    )
                    Text(
                        text = "$incidentCount suspicious / rogue events recorded",
                        color = Color.White,
                        fontSize = 13.sp,
                        modifier = Modifier.padding(top = 2.dp)
                    )
                }
                Button(
                    onClick = onExport,
                    colors = ButtonDefaults.buttonColors(containerColor = CyberCyan, contentColor = Color.Black)
                ) {
                    Text("Export Report", fontWeight = FontWeight.Bold, fontSize = 12.sp)
                }
            }
        }
    }
}

