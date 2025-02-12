package com.example.dynamicAnalysisDetector

import android.content.Context
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.getValue
import androidx.compose.runtime.setValue
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.launch
import android.util.Log
import com.example.dynamicAnalysisDetector.R

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            EvasionCheckerTheme {
                Surface(
                    modifier = Modifier.fillMaxWidth(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    EvasionCheckList(context = this@MainActivity)
                }
            }
        }
    }
}

@Composable
fun EvasionCheckerTheme(content: @Composable () -> Unit) {
    MaterialTheme {
        content()
    }
}

@Composable
fun EvasionCheckList(context: Context) {
    var detections by remember { mutableStateOf<List<DetectionItem>>(emptyList()) }
    val scope = rememberCoroutineScope()

    fun refreshDetections() {
        Log.d("EvasionCheckList", "Refresh triggered!")
        scope.launch {
            detections = EvasionDetector.getAllDetections(context)
        }
    }

    LaunchedEffect(Unit) {
        refreshDetections()
    }

    // Group detections by category
    val groupedDetections: Map<String, List<DetectionItem>> = detections.groupBy { it.category }

    Column(modifier = Modifier.fillMaxWidth()) {
        Button(
            onClick = { refreshDetections() },
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp)
        ) {
            Text(text = "Refresh")
        }

        LazyColumn(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            groupedDetections.forEach { (category, items) ->
                item {
                    CategoryCard(category = category, items = items)
                }
            }
        }
    }
}

@Composable
fun CategoryCard(category: String, items: List<DetectionItem>) {
    var expanded by remember { mutableStateOf(false) }
    Card(
        elevation = CardDefaults.cardElevation(4.dp),
        modifier = Modifier
            .fillMaxWidth()
            .clickable { expanded = !expanded }
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.fillMaxWidth()
            ) {
                Text(
                    text = "Category: $category",
                    fontSize = 20.sp,
                    modifier = Modifier.weight(1f)
                )
                Icon(
                    painter = painterResource(
                        id = if (expanded) R.drawable.ic_check else R.drawable.ic_cross
                    ),
                    contentDescription = if (expanded) "Collapse" else "Expand"
                )
            }
            if (expanded) {
                Spacer(modifier = Modifier.height(8.dp))
                items.forEach { detection ->
                    DetectionRow(detection = detection)
                    Spacer(modifier = Modifier.height(8.dp))
                }
            }
        }
    }
}

@Composable
fun DetectionRow(detection: DetectionItem) {
    Row(
        verticalAlignment = Alignment.CenterVertically,
        modifier = Modifier
            .fillMaxWidth()
            .padding(start = 8.dp)
    ) {
        Icon(
            painter = painterResource(
                id = if (detection.detected) R.drawable.ic_check else R.drawable.ic_cross
            ),
            contentDescription = null,
            tint = if (detection.detected) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.error,
            modifier = Modifier
                .height(24.dp)
                .padding(end = 8.dp)
        )
        Column {
            Text(
                text = detection.method,
                fontSize = 16.sp,
                color = MaterialTheme.colorScheme.onBackground
            )
            Spacer(modifier = Modifier.height(4.dp))
            Text(
                text = detection.description,
                fontSize = 14.sp,
                color = MaterialTheme.colorScheme.onBackground
            )
        }
    }
}
