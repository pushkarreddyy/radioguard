package com.security.radioguard.ui.screens

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Block
import androidx.compose.material.icons.filled.CloudDownload
import androidx.compose.material.icons.filled.GppBad
import androidx.compose.material.icons.filled.GppGood
import androidx.compose.material.icons.filled.GppMaybe
import androidx.compose.material.icons.filled.Radar
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.drawscope.Stroke
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
    quarantinedCount: Int = 0,
    deviceStatus: com.security.radioguard.security.DeviceIntegritySentry.IntegrityStatus,
    onToggleSentry: (Boolean) -> Unit,
    onToggleVpn: (Boolean) -> Unit,
    onBreakTowerLock: () -> Unit,
    onExportIncidents: () -> Unit,
    onSyncRegionalDataset: (String) -> Unit = {}
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

        // Cellular Geospatial Radar & Vector Card
        CellularRadarCard(report = report)

        Spacer(modifier = Modifier.height(16.dp))

        // Active Connection Details
        ActiveCellDetailsCard(report = report)

        Spacer(modifier = Modifier.height(16.dp))

        // Rogue Cell Quarantine Blacklist Card
        RogueQuarantineCard(quarantinedCount = quarantinedCount)

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

        // Offline Regional Ground-Truth Dataset Packs & Database Status
        DatabaseStatusCard(
            totalVerifiedTowers = totalVerifiedTowers,
            onSyncRegionalDataset = onSyncRegionalDataset
        )
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
fun DatabaseStatusCard(
    totalVerifiedTowers: Int,
    onSyncRegionalDataset: (String) -> Unit
) {
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
                Text(
                    text = "OFFLINE GROUND-TRUTH DATABASE",
                    color = CyberCyan,
                    fontWeight = FontWeight.Bold,
                    fontSize = 12.sp,
                    fontFamily = FontFamily.Monospace
                )
                Icon(
                    imageVector = Icons.Default.CloudDownload,
                    contentDescription = null,
                    tint = CyberCyan,
                    modifier = Modifier.size(18.dp)
                )
            }

            Spacer(modifier = Modifier.height(8.dp))

            Text(
                text = "Verified Macro-Towers: $totalVerifiedTowers",
                color = Color.White,
                fontWeight = FontWeight.Bold,
                fontSize = 14.sp
            )
            Text(
                text = "Offline cryptographic spatial baseline loaded in local SQLite. Fast-sync regional carrier datasets for offline IMSI-catcher trapping:",
                color = Color.Gray,
                fontSize = 11.sp,
                modifier = Modifier.padding(top = 4.dp)
            )

            Spacer(modifier = Modifier.height(12.dp))

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                OutlinedButton(
                    onClick = { onSyncRegionalDataset("US") },
                    modifier = Modifier.weight(1f),
                    contentPadding = PaddingValues(horizontal = 4.dp, vertical = 6.dp)
                ) {
                    Text("US (FCC)", fontSize = 11.sp, maxLines = 1)
                }
                OutlinedButton(
                    onClick = { onSyncRegionalDataset("EU") },
                    modifier = Modifier.weight(1f),
                    contentPadding = PaddingValues(horizontal = 4.dp, vertical = 6.dp)
                ) {
                    Text("EU (ETSI)", fontSize = 11.sp, maxLines = 1)
                }
                OutlinedButton(
                    onClick = { onSyncRegionalDataset("ASIA") },
                    modifier = Modifier.weight(1f),
                    contentPadding = PaddingValues(horizontal = 4.dp, vertical = 6.dp)
                ) {
                    Text("ASIA", fontSize = 11.sp, maxLines = 1)
                }
                Button(
                    onClick = { onSyncRegionalDataset("GLOBAL") },
                    modifier = Modifier.weight(1f),
                    colors = ButtonDefaults.buttonColors(containerColor = CyberCyan, contentColor = Color.Black),
                    contentPadding = PaddingValues(horizontal = 4.dp, vertical = 6.dp)
                ) {
                    Text("ALL", fontSize = 11.sp, fontWeight = FontWeight.Bold, maxLines = 1)
                }
            }
        }
    }
}

@Composable
fun CellularRadarCard(report: AnomalyReport?) {
    val obs = report?.observation
    val level = report?.threatLevel ?: ThreatLevel.SAFE
    val radarColor = when (level) {
        ThreatLevel.SAFE -> ThreatGreen
        ThreatLevel.SUSPICIOUS -> ThreatYellow
        ThreatLevel.CRITICAL_ROGUE -> ThreatRed
    }

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
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        imageVector = Icons.Default.Radar,
                        contentDescription = null,
                        tint = CyberCyan,
                        modifier = Modifier.size(18.dp)
                    )
                    Spacer(modifier = Modifier.width(6.dp))
                    Text(
                        text = "CELLULAR GEOSPATIAL RADAR",
                        color = CyberCyan,
                        fontWeight = FontWeight.Bold,
                        fontSize = 12.sp,
                        fontFamily = FontFamily.Monospace
                    )
                }
                Text(
                    text = if (obs != null) "LIVE RF SWEEP" else "STANDBY",
                    color = radarColor,
                    fontSize = 10.sp,
                    fontWeight = FontWeight.Bold,
                    fontFamily = FontFamily.Monospace
                )
            }

            Spacer(modifier = Modifier.height(12.dp))

            // Canvas Radar Graphic
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .height(140.dp)
                    .background(Color(0xFF0A0E14), RoundedCornerShape(8.dp)),
                contentAlignment = Alignment.Center
            ) {
                Canvas(modifier = Modifier.fillMaxSize().padding(12.dp)) {
                    val center = Offset(size.width / 2f, size.height / 2f)
                    val maxRadius = minOf(size.width, size.height) / 2f * 0.9f

                    // Draw concentric distance rings
                    val ringSteps = listOf(0.33f, 0.66f, 1.0f)
                    ringSteps.forEach { fraction ->
                        drawCircle(
                            color = CyberCyan.copy(alpha = 0.25f),
                            radius = maxRadius * fraction,
                            center = center,
                            style = Stroke(width = 1.dp.toPx())
                        )
                    }

                    // Crosshairs
                    drawLine(
                        color = CyberCyan.copy(alpha = 0.2f),
                        start = Offset(center.x, center.y - maxRadius),
                        end = Offset(center.x, center.y + maxRadius),
                        strokeWidth = 1.dp.toPx()
                    )
                    drawLine(
                        color = CyberCyan.copy(alpha = 0.2f),
                        start = Offset(center.x - maxRadius, center.y),
                        end = Offset(center.x + maxRadius, center.y),
                        strokeWidth = 1.dp.toPx()
                    )

                    // Center user position
                    drawCircle(
                        color = CyberCyan,
                        radius = 4.dp.toPx(),
                        center = center
                    )

                    if (obs != null) {
                        // Plot serving cell vector
                        val ta = obs.timingAdvance ?: 1
                        val distFraction = (ta / 30f).coerceIn(0.25f, 0.95f)
                        val angleRad = -Math.PI / 4.0 // 45 degrees north-east
                        val servingX = center.x + (maxRadius * distFraction * Math.cos(angleRad)).toFloat()
                        val servingY = center.y + (maxRadius * distFraction * Math.sin(angleRad)).toFloat()

                        // Serving vector line
                        drawLine(
                            color = radarColor.copy(alpha = 0.6f),
                            start = center,
                            end = Offset(servingX, servingY),
                            strokeWidth = 2.dp.toPx()
                        )

                        // Serving cell blip
                        drawCircle(
                            color = radarColor,
                            radius = 6.dp.toPx(),
                            center = Offset(servingX, servingY)
                        )

                        // Neighbor blips
                        val neighborCount = obs.neighborCount.coerceAtMost(6)
                        for (i in 0 until neighborCount) {
                            val neighborAngle = (i * (2 * Math.PI / 6.0)) + 1.2
                            val nDist = maxRadius * (0.45f + (i % 3) * 0.18f)
                            val nx = center.x + (nDist * Math.cos(neighborAngle)).toFloat()
                            val ny = center.y + (nDist * Math.sin(neighborAngle)).toFloat()
                            drawCircle(
                                color = Color.Gray.copy(alpha = 0.7f),
                                radius = 3.dp.toPx(),
                                center = Offset(nx, ny)
                            )
                        }
                    }
                }
            }

            Spacer(modifier = Modifier.height(12.dp))

            // Vector metrics
            if (obs != null) {
                val taVal = obs.timingAdvance?.toString() ?: "N/A"
                val distEst = if (obs.timingAdvance != null) "~${obs.timingAdvance * 550}m" else "Line of Sight"
                val neighborDominance = if (obs.maxNeighborRsrpDbm != null) {
                    val delta = obs.rsrpDbm - obs.maxNeighborRsrpDbm
                    "+${delta} dB Margin"
                } else {
                    "Isolated (No Neighbors)"
                }

                CellMetricRow(label = "Timing Advance (Vector)", value = "$taVal ($distEst)")
                CellMetricRow(label = "RF Dominance vs Neighbors", value = neighborDominance)
                CellMetricRow(label = "eNodeB / Sector Topology", value = "eNB ${obs.cellId / 256} : Sec ${obs.cellId % 256}")
                CellMetricRow(label = "Wi-Fi Geofence Anchor", value = if (obs.wifiBssid != null) "Locked (${obs.wifiBssid.take(8)}...)" else "Unanchored")
            } else {
                Text(
                    text = "No active baseband RF vectors detected.",
                    color = Color.Gray,
                    fontSize = 12.sp
                )
            }
        }
    }
}

@Composable
fun RogueQuarantineCard(quarantinedCount: Int) {
    val isArmed = quarantinedCount > 0
    val badgeColor = if (isArmed) ThreatRed else ThreatGreen

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
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        imageVector = if (isArmed) Icons.Default.Block else Icons.Default.Security,
                        contentDescription = null,
                        tint = badgeColor,
                        modifier = Modifier.size(18.dp)
                    )
                    Spacer(modifier = Modifier.width(6.dp))
                    Text(
                        text = "ROGUE QUARANTINE BLACKLIST",
                        color = CyberCyan,
                        fontWeight = FontWeight.Bold,
                        fontSize = 12.sp,
                        fontFamily = FontFamily.Monospace
                    )
                }
                Text(
                    text = if (isArmed) "ENFORCING" else "CLEAR",
                    color = badgeColor,
                    fontSize = 11.sp,
                    fontWeight = FontWeight.Bold,
                    fontFamily = FontFamily.Monospace
                )
            }

            Spacer(modifier = Modifier.height(8.dp))

            Text(
                text = "$quarantinedCount Malicious Cell Signatures Blocked",
                color = Color.White,
                fontWeight = FontWeight.Bold,
                fontSize = 14.sp
            )

            Text(
                text = if (isArmed) {
                    "Baseband handovers to these quarantined eNodeB/CID nodes are strictly intercepted. Automated Shizuku radio resets break forced rogue locks."
                } else {
                    "Zero quarantined rogue cells. All observed baseband towers meet cryptographic and physical RF propagation verifications."
                },
                color = Color.LightGray,
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

