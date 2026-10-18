use serde_json::{json, Value};
use std::{
    collections::HashMap,
    thread,
    time::{Duration, Instant},
};
use sysinfo::{Disks, Networks, System};

pub struct HostCollector {
    system: System,
    networks: Networks,
    previous_network: HashMap<String, (u64, u64)>,
    previous_at: Option<Instant>,
}

impl Default for HostCollector {
    fn default() -> Self {
        Self {
            system: System::new_all(),
            networks: Networks::new_with_refreshed_list(),
            previous_network: HashMap::new(),
            previous_at: None,
        }
    }
}

impl HostCollector {
    pub fn collect(&mut self) -> Value {
        let cpu_start = Instant::now();
        self.system.refresh_cpu_usage();
        thread::sleep(sysinfo::MINIMUM_CPU_UPDATE_INTERVAL.max(Duration::from_millis(200)));
        self.system.refresh_cpu_usage();
        let cpu_window_seconds = cpu_start.elapsed().as_secs_f64();
        self.system.refresh_memory();
        self.networks.refresh(true);
        let now = Instant::now();
        let elapsed = self
            .previous_at
            .map(|previous| now.duration_since(previous).as_secs_f64());
        let mut interfaces = Vec::new();
        let mut next_network = HashMap::new();
        for (name, data) in &self.networks {
            let received = data.total_received();
            let transmitted = data.total_transmitted();
            let previous = self.previous_network.get(name);
            let (rx_rate, tx_rate, quality) = match (previous, elapsed) {
                (Some((rx, tx)), Some(seconds))
                    if received >= *rx && transmitted >= *tx && seconds > 0.0 =>
                {
                    (
                        Some((received - rx) as f64 / seconds),
                        Some((transmitted - tx) as f64 / seconds),
                        "measured",
                    )
                }
                (Some(_), Some(_)) => (None, None, "counter_reset"),
                _ => (None, None, "baseline_required"),
            };
            interfaces.push(json!({"name":name,"receivedBytes":received.to_string(),"transmittedBytes":transmitted.to_string(),
                "receivedBytesPerSecond":rx_rate,"transmittedBytesPerSecond":tx_rate,"rateQuality":quality,"intervalSeconds":elapsed,
                "receivedPackets":data.total_packets_received().to_string(),"transmittedPackets":data.total_packets_transmitted().to_string(),
                "receiveErrors":data.total_errors_on_received().to_string(),"transmitErrors":data.total_errors_on_transmitted().to_string()}));
            next_network.insert(name.clone(), (received, transmitted));
        }
        self.previous_network = next_network;
        self.previous_at = Some(now);
        let disks = Disks::new_with_refreshed_list();
        let disks: Vec<Value> = disks.iter().map(|disk| json!({"name":disk.name().to_string_lossy(),"mountPoint":disk.mount_point().to_string_lossy(),
            "fileSystem":disk.file_system().to_string_lossy(),"totalBytes":disk.total_space().to_string(),"availableBytes":disk.available_space().to_string(),
            "removable":disk.is_removable(),"readOnly":disk.is_read_only()})).collect();
        let load = if cfg!(target_os = "windows") {
            Value::Null
        } else {
            let load = System::load_average();
            json!({"one":load.one,"five":load.five,"fifteen":load.fifteen})
        };
        json!({
            "hostname":System::host_name(),"os":std::env::consts::OS,"osVersion":System::long_os_version(),"kernelVersion":System::kernel_version(),"architecture":std::env::consts::ARCH,
            "uptimeSeconds":System::uptime().to_string(),"bootTimeUnixSeconds":System::boot_time().to_string(),
            "cpu":{"usagePercent":self.system.global_cpu_usage(),"logicalCount":self.system.cpus().len(),"sampleWindowSeconds":cpu_window_seconds,"quality":"measured"},
            "memory":{"totalBytes":self.system.total_memory().to_string(),"availableBytes":self.system.available_memory().to_string(),"usedBytes":self.system.used_memory().to_string(),
                "swapTotalBytes":self.system.total_swap().to_string(),"swapUsedBytes":self.system.used_swap().to_string()},
            "networkInterfaces":interfaces,"disks":disks,"loadAverage":load,
            "capabilities":{"cpu":true,"memory":true,"networkCounters":true,"diskCapacity":true,"diskIO":false,"processes":false,"loginAudit":false,"windowsLoadAverage":false}
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn actual_host_sample_has_decimal_counters_and_no_invented_first_rates() {
        let mut host = HostCollector::default();
        let sample = host.collect();
        assert!(
            sample["memory"]["totalBytes"]
                .as_str()
                .unwrap()
                .parse::<u64>()
                .unwrap()
                > 0
        );
        assert!(sample["cpu"]["logicalCount"].as_u64().unwrap() > 0);
        for item in sample["networkInterfaces"].as_array().unwrap() {
            assert!(item["receivedBytes"].is_string());
            assert!(item["receivedBytesPerSecond"].is_null());
            assert_eq!(item["rateQuality"], "baseline_required");
        }
        assert_eq!(sample["capabilities"]["loginAudit"], false);
    }
}
