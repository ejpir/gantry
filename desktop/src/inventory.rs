use serde::Deserialize;

/// Read-model subset of api/managerapi/types.go. Unknown fields are accepted so
/// additive manager changes do not require a desktop release.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BootSettings {
    #[serde(rename = "memoryMiB")]
    pub memory_mib: u64,
    pub cpus: u32,
    pub process_isolation: String,
    pub dev_containers: bool,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Sandbox {
    pub name: String,
    pub state: String,
    pub desired: BootSettings,
    pub active: Option<BootSettings>,
    #[serde(default)]
    pub restart_required: bool,
    #[serde(default)]
    pub image: String,
    #[serde(default)]
    pub image_ref: String,
    #[serde(default)]
    pub image_digest: String,
    #[serde(default)]
    pub pid: u32,
    #[serde(default)]
    pub writable: bool,
}

impl Sandbox {
    pub fn image_label(&self) -> &str {
        if !self.image_ref.is_empty() {
            &self.image_ref
        } else if !self.image.is_empty() {
            &self.image
        } else {
            "Unknown image"
        }
    }

    /// Never present next-boot settings as a running VM's current allocation.
    pub fn displayed_resources(&self) -> Option<&BootSettings> {
        match self.state.as_str() {
            "running" => self.active.as_ref(),
            "starting" | "stopped" => Some(&self.desired),
            _ => None,
        }
    }

    pub fn resource_label(&self) -> &'static str {
        match self.state.as_str() {
            "running" => "Current allocation",
            "starting" => "Requested allocation",
            "stopped" => "Next boot",
            _ => "Allocation unavailable",
        }
    }

    pub fn state_label(&self) -> &str {
        match self.state.as_str() {
            "running" => "Running",
            "starting" => "Starting",
            "stopped" => "Stopped",
            _ => "Unknown",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Filter {
    #[default]
    All,
    Running,
    Stopped,
}

impl Filter {
    pub fn label(self) -> &'static str {
        match self {
            Self::All => "All",
            Self::Running => "Running",
            Self::Stopped => "Stopped",
        }
    }

    fn matches(self, sandbox: &Sandbox) -> bool {
        match self {
            Self::All => true,
            Self::Running => sandbox.state == "running",
            Self::Stopped => sandbox.state == "stopped",
        }
    }
}

#[derive(Default)]
pub struct Inventory {
    rows: Vec<Sandbox>,
    pub query: String,
    pub filter: Filter,
    selected: Option<String>,
}

impl Inventory {
    pub fn replace(&mut self, mut rows: Vec<Sandbox>) {
        let initially_empty = self.rows.is_empty();
        rows.sort_by(|a, b| a.name.cmp(&b.name));
        self.rows = rows;
        self.reconcile_selection(initially_empty);
    }

    pub fn set_query(&mut self, query: String) {
        self.query = query;
        self.reconcile_selection(true);
    }

    pub fn set_filter(&mut self, filter: Filter) {
        self.filter = filter;
        self.reconcile_selection(true);
    }

    pub fn select(&mut self, name: &str) {
        if self.visible().iter().any(|row| row.name == name) {
            self.selected = Some(name.to_owned());
        }
    }

    pub fn clear_selection(&mut self) {
        self.selected = None;
    }

    pub fn selected(&self) -> Option<&Sandbox> {
        self.rows
            .iter()
            .find(|row| Some(&row.name) == self.selected.as_ref())
    }

    pub fn rows(&self) -> &[Sandbox] {
        &self.rows
    }

    pub fn visible(&self) -> Vec<&Sandbox> {
        let query = self.query.trim().to_lowercase();
        self.rows
            .iter()
            .filter(|row| {
                self.filter.matches(row)
                    && (query.is_empty()
                        || row.name.to_lowercase().contains(&query)
                        || row.image_label().to_lowercase().contains(&query)
                        || row.state.to_lowercase().contains(&query))
            })
            .collect()
    }

    fn reconcile_selection(&mut self, select_first: bool) {
        let visible = self.visible();
        if (select_first || self.selected.is_some())
            && !visible
                .iter()
                .any(|row| Some(&row.name) == self.selected.as_ref())
        {
            self.selected = visible.first().map(|row| row.name.clone());
        }
    }
}

pub fn memory_label(mib: u64) -> String {
    if mib >= 1024 && mib.is_multiple_of(1024) {
        format!("{} GiB", mib / 1024)
    } else {
        format!("{mib} MiB")
    }
}

/// Explicit demo data also serves as a wire-format fixture. Never used as a
/// fallback when the real manager is unavailable.
pub fn demo_sandboxes() -> Vec<Sandbox> {
    serde_json::from_str(include_str!("../fixtures/sandboxes.json"))
        .expect("bundled sandbox fixture must match the manager read model")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_manager_field_names_and_active_allocation() {
        let rows = demo_sandboxes();
        let dev = rows.iter().find(|row| row.name == "dev").unwrap();
        assert_eq!(dev.desired.memory_mib, 4096);
        assert_eq!(dev.active.as_ref().unwrap().memory_mib, 2048);
        assert_eq!(dev.displayed_resources().unwrap().cpus, 2);
        assert!(dev.restart_required);
        assert_eq!(dev.image_label(), "debian:bookworm-slim");
    }

    #[test]
    fn unknown_active_allocation_is_not_replaced_with_saved_values() {
        let mut row = demo_sandboxes().remove(0);
        row.state = "running".into();
        row.active = None;
        assert!(row.displayed_resources().is_none());
        row.state = "future-state".into();
        assert_eq!(row.state_label(), "Unknown");
        assert!(row.displayed_resources().is_none());
        row.state = "stopped".into();
        assert_eq!(row.displayed_resources(), Some(&row.desired));
    }

    #[test]
    fn selection_survives_refresh_reordering_and_resource_changes() {
        let mut inventory = Inventory::default();
        inventory.replace(demo_sandboxes());
        inventory.select("dev");
        let mut rows = demo_sandboxes();
        rows.reverse();
        rows.iter_mut()
            .find(|row| row.name == "dev")
            .unwrap()
            .desired
            .cpus = 8;
        inventory.replace(rows);
        assert_eq!(inventory.selected().unwrap().name, "dev");
        assert_eq!(inventory.selected().unwrap().desired.cpus, 8);
    }

    #[test]
    fn filtering_matches_image_and_preserves_query_across_refresh() {
        let mut inventory = Inventory::default();
        inventory.replace(demo_sandboxes());
        inventory.set_query(" DEBIAN ".into());
        assert_eq!(inventory.visible().len(), 1);
        assert_eq!(inventory.selected().unwrap().name, "dev");
        inventory.replace(demo_sandboxes());
        assert_eq!(inventory.query, " DEBIAN ");
        inventory.set_filter(Filter::Stopped);
        assert!(inventory.visible().is_empty());
        assert!(inventory.selected().is_none());
    }

    #[test]
    fn removed_or_disconnected_rows_cannot_remain_selected() {
        let mut inventory = Inventory::default();
        inventory.replace(demo_sandboxes());
        inventory.select("dev");
        inventory.replace(
            demo_sandboxes()
                .into_iter()
                .filter(|row| row.name != "dev")
                .collect(),
        );
        assert_ne!(inventory.selected().unwrap().name, "dev");
        inventory.replace(vec![]);
        assert!(inventory.visible().is_empty());
        assert!(inventory.selected().is_none());
    }

    #[test]
    fn explicit_deselection_survives_polling() {
        let mut inventory = Inventory::default();
        inventory.replace(demo_sandboxes());
        inventory.clear_selection();
        inventory.replace(demo_sandboxes());
        assert!(inventory.selected().is_none());
    }

    #[test]
    fn resource_labels_do_not_round_allocations() {
        assert_eq!(memory_label(512), "512 MiB");
        assert_eq!(memory_label(2048), "2 GiB");
        assert_eq!(memory_label(1536), "1536 MiB");
    }
}
