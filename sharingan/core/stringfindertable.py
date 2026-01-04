import ida_kernwin
import idaapi
from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QAction
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QCheckBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMenu,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

class StringFinderTable(QWidget):
    def __init__(self, string_finder):
        super().__init__()
        self.string_finder = string_finder
        self.string_results = []
        self.string_row_checkboxes = []
        self._last_checkbox_row = None
        self.checkbox_header_index = 0
        self.tbl_string = QTableWidget()
        self.btn_scan_code = QPushButton("Scan code", self)
        self.btn_ignore_strings = QPushButton("Ignore", self)
        self.btn_show_hex = QPushButton("Show Hex", self)
        self.lbl_string_count = QLabel("0 string", self)
        self.show_hex_mode = False
        self.sort_column = -1
        self.sort_ascending = True
        self._build_workspace()

    def _build_workspace(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        self.btn_scan_code.clicked.connect(self.scan_code_strings)
        self.btn_ignore_strings.clicked.connect(self.ignore_selected_strings)
        self.btn_show_hex.clicked.connect(self.show_hex_values)

        button_bar = QHBoxLayout()
        button_bar.addWidget(self.btn_scan_code)
        button_bar.addWidget(self.btn_ignore_strings)
        button_bar.addWidget(self.btn_show_hex)
        button_bar.addStretch()
        
        # String count label beside buttons
        self.lbl_string_count.setStyleSheet("font-weight: bold; padding: 5px;")
        self.lbl_string_count.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        button_bar.addWidget(self.lbl_string_count)
        
        layout.addLayout(button_bar)

        self.tbl_string.setColumnCount(7)
        self.tbl_string.setHorizontalHeaderLabels(
            ["", "#", "Raw", "Address", "Preview", "Xref", "Type"]
        )
        self.tbl_string.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.tbl_string.setSelectionMode(QAbstractItemView.SingleSelection)
        self.tbl_string.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.tbl_string.verticalHeader().setVisible(False)
        self.tbl_string.horizontalHeader().setStretchLastSection(False)
        
        # Enable sorting
        self.tbl_string.setSortingEnabled(False)  # Disable during population, enable after
        self.tbl_string.horizontalHeader().sectionClicked.connect(self.sort_by_column)
        self.tbl_string.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)  # Checkbox
        self.tbl_string.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)  # #
        self.tbl_string.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)          # Raw
        self.tbl_string.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)  # Address
        self.tbl_string.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)          # Preview
        self.tbl_string.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeToContents)  # Xref
        self.tbl_string.horizontalHeader().setSectionResizeMode(6, QHeaderView.ResizeToContents)  # Type

        header = self.tbl_string.horizontalHeader()
        self.checkbox_header_container = QWidget(header)
        container_layout = QHBoxLayout(self.checkbox_header_container)
        container_layout.setContentsMargins(0, 0, 0, 0)
        container_layout.setAlignment(Qt.AlignCenter)
        self.checkbox_header_button = QToolButton(self.checkbox_header_container)
        self.checkbox_header_button.setAutoRaise(True)
        self.checkbox_header_button.setCursor(Qt.PointingHandCursor)
        self.checkbox_header_button.setToolTip("Toggle all selections")
        self.checkbox_header_button.clicked.connect(self._handle_header_checkbox_button)
        container_layout.addWidget(self.checkbox_header_button)
        header.sectionResized.connect(self._position_checkbox_header_button)
        header.sectionMoved.connect(self._position_checkbox_header_button)
        header.geometriesChanged.connect(self._position_checkbox_header_button)
        self.tbl_string.setContextMenuPolicy(Qt.CustomContextMenu)
        self.tbl_string.customContextMenuRequested.connect(
            self._show_table_context_menu
        )
        self.tbl_string.horizontalScrollBar().valueChanged.connect(
            self._position_checkbox_header_button
        )

        layout.addWidget(self.tbl_string)
        self._initialize_string_table_placeholders()
        self._update_checkbox_header_label()
        QTimer.singleShot(0, self._position_checkbox_header_button)

    def _initialize_string_table_placeholders(self):
        self.tbl_string.setRowCount(1)
        self.tbl_string.clearContents()
        self.string_row_checkboxes.clear()
        self._last_checkbox_row = None
        for col in range(1, 7):
            align = Qt.AlignCenter if col in (1, 3) else None  # Center # and Address
            tooltip = "0" if col == 2 else None
            self.tbl_string.setItem(
                0, col, self._make_table_item("0", align=align, tooltip=tooltip)
            )
        self._add_checkbox_to_row(0, enabled=False, track=False)

    def _make_table_item(
        self, text: str, align: Qt.Alignment | None = None, tooltip: str | None = None
    ):
        item = QTableWidgetItem(text)
        flags = item.flags()
        item.setFlags(flags & ~Qt.ItemIsEditable)
        if align is not None:
            item.setTextAlignment(align)
        if tooltip:
            item.setToolTip(tooltip)
        return item

    def _add_checkbox_to_row(self, row: int, enabled: bool = True, track: bool = True):
        checkbox = QCheckBox(self.tbl_string)
        checkbox.setEnabled(enabled)
        if enabled:
            checkbox.stateChanged.connect(self._on_row_checkbox_state_changed)
            checkbox.clicked.connect(
                lambda checked, r=row: self._handle_row_checkbox_clicked(r, checked)
            )
        container = QWidget()
        layout = QHBoxLayout(container)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setAlignment(Qt.AlignCenter)
        layout.addWidget(checkbox)
        self.tbl_string.setCellWidget(row, self.checkbox_header_index, container)
        if enabled and track:
            self.string_row_checkboxes.append(checkbox)

    def _on_row_checkbox_state_changed(self, _state):
        self._update_checkbox_header_label()

    def _handle_row_checkbox_clicked(self, row: int, checked: bool):
        self._select_row_from_checkbox(row)
        modifiers = QApplication.keyboardModifiers()
        if modifiers & Qt.ShiftModifier and self._last_checkbox_row is not None:
            self._set_checkbox_range_state(self._last_checkbox_row, row, checked)
        self._last_checkbox_row = row

    def _set_checkbox_range_state(self, start_row: int, end_row: int, state: bool):
        if not self.string_row_checkboxes:
            return
        lower = max(0, min(start_row, end_row))
        upper = min(len(self.string_row_checkboxes) - 1, max(start_row, end_row))
        for idx in range(lower, upper + 1):
            checkbox = self.string_row_checkboxes[idx]
            checkbox.blockSignals(True)
            checkbox.setChecked(state)
            checkbox.blockSignals(False)
        self._update_checkbox_header_label()

    def _select_row_from_checkbox(self, row: int):
        if 0 <= row < self.tbl_string.rowCount():
            self.tbl_string.selectRow(row)

    def _show_table_context_menu(self, pos):
        index = self.tbl_string.indexAt(pos)
        if not index.isValid():
            return
        row = index.row()
        col = index.column()
        self.tbl_string.selectRow(row)

        menu = QMenu(self.tbl_string)
        if col == 2:
            action = QAction("Copy Raw", menu)
            action.triggered.connect(lambda: self._copy_to_clipboard(row, "value"))
            menu.addAction(action)
        if col == 3:
            action_copy = QAction("Copy Address", menu)
            action_copy.triggered.connect(lambda: self._copy_to_clipboard(row, "address"))
            menu.addAction(action_copy)
            action_jump = QAction("Jump to Address", menu)
            action_jump.triggered.connect(lambda: self._jump_to_address(row))
            menu.addAction(action_jump)
        if col == 4:
            action = QAction("Copy Preview", menu)
            action.triggered.connect(lambda: self._copy_to_clipboard(row, "preview"))
            menu.addAction(action)
        if col == 5:
            action_show = QAction("Show Xrefs", menu)
            action_show.triggered.connect(lambda: self._print_xrefs(row))
            menu.addAction(action_show)
            action_copy = QAction("Copy Xrefs", menu)
            action_copy.triggered.connect(lambda: self._copy_to_clipboard(row, "xrefs"))
            menu.addAction(action_copy)
        if col == 6:
            action = QAction("Copy Type", menu)
            action.triggered.connect(lambda: self._copy_to_clipboard(row, "type"))
            menu.addAction(action)

        if menu.actions():
            menu.exec_(self.tbl_string.viewport().mapToGlobal(pos))

    def _copy_to_clipboard(self, row: int, field: str):
        if not (0 <= row < len(self.string_results)):
            return
        entry = self.string_results[row]
        raw = entry.get(field, "") if isinstance(entry, dict) else entry
        QApplication.clipboard().setText(str(raw))

    def _jump_to_address(self, row: int):
        if not (0 <= row < len(self.string_results)):
            return
        entry = self.string_results[row]
        address = entry.get("address") if isinstance(entry, dict) else entry
        idaapi.jumpto(address)

    @staticmethod
    def _normalize_ea(value):
        if value is None:
            return None
        if isinstance(value, int):
            return value
        if isinstance(value, str):
            try:
                return int(value, 16) if value.lower().startswith("0x") else int(value)
            except ValueError:
                return None
        return None

    def _print_xrefs(self, row: int):
        if not (0 <= row < len(self.string_results)):
            idaapi.msg("[Sharingan] No xref data for this row.\n")
            return
        entry = self.string_results[row]
        if not isinstance(entry, dict):
            idaapi.msg("[Sharingan] No xref data for this row.\n")
            return

        raw_xrefs = entry.get("xrefs") or []
        normalized = [
            ea for ea in (self._normalize_ea(x) for x in raw_xrefs) if ea is not None
        ]
        if not normalized:
            idaapi.msg("[Sharingan] No xrefs recorded for the selected string.\n")
            return

        formatted = ", ".join(f"0x{ea:08X}" for ea in normalized)
        idaapi.msg(f"[Sharingan] Xrefs for row {row + 1}: {formatted}\n")

    def _update_checkbox_header_label(self):
        if not hasattr(self, "checkbox_header_button"):
            return
        self.checkbox_header_button.setText(
            "\u2611" if self._are_all_rows_checked() else "\u2610"
        )

    def _are_all_rows_checked(self) -> bool:
        return bool(self.string_row_checkboxes) and all(
            cb.isChecked() for cb in self.string_row_checkboxes
        )

    def _set_all_row_checkboxes(self, state: bool):
        for cb in self.string_row_checkboxes:
            cb.blockSignals(True)
            cb.setChecked(state)
            cb.blockSignals(False)
        self._last_checkbox_row = None
        self._update_checkbox_header_label()

    def _handle_header_checkbox_button(self):
        select_all = not self._are_all_rows_checked()
        self._set_all_row_checkboxes(select_all)

    def _position_checkbox_header_button(self, *args):
        if (
            not hasattr(self, "checkbox_header_container")
            or not self.checkbox_header_container
        ):
            return
        header = self.tbl_string.horizontalHeader()
        if self.checkbox_header_index >= header.count():
            return
        x = header.sectionViewportPosition(self.checkbox_header_index)
        width = header.sectionSize(self.checkbox_header_index)
        self.checkbox_header_container.setGeometry(x, 0, width, header.height())
        self.checkbox_header_container.show()

    def get_selected_string_rows(self):
        selected_rows = []
        for idx, checkbox in enumerate(self.string_row_checkboxes):
            if checkbox.isEnabled() and checkbox.isChecked():
                selected_rows.append(idx)
        return selected_rows

    def get_string_table_snapshot(self):
        if not self.string_results:
            return []
        snapshot = []
        for item in self.string_results:
            if isinstance(item, dict):
                snapshot.append((item.get("value", ""), item.get("address")))
            else:
                snapshot.append((item, None))
        return snapshot

    def _apply_preview_to_row(self, row: int, preview_value) -> bool:
        if not (0 <= row < len(self.string_results)):
            return False
        entry = self.string_results[row]
        if isinstance(entry, dict):
            entry["preview"] = preview_value
        text = str(preview_value)
        table_item = self.tbl_string.item(row, 4)  # Preview is column 4
        if table_item:
            table_item.setText(text)
            table_item.setToolTip(text)
        else:
            self.tbl_string.setItem(row, 4, self._make_table_item(text, tooltip=text))
        return True

    def update_preview_at_location(self, ea, preview_value):
        if ea is None or not self.string_results:
            return False

        target = self._normalize_ea(ea)
        if target is None:
            return False

        updated = False
        for row, entry in enumerate(self.string_results):
            current = self._normalize_ea(
                entry.get("address") if isinstance(entry, dict) else None
            )
            if current != target:
                continue
            if self._apply_preview_to_row(row, preview_value):
                updated = True
        return updated

    def update_preview_row(self, row_index: int, preview_value):
        return self._apply_preview_to_row(row_index, preview_value)

    def scan_code_strings(self):
        if self.string_finder is None:
            idaapi.msg("[Sharingan] String Finder modules unavailable.\n")
            return
        self.btn_scan_code.setEnabled(False)
        self.btn_scan_code.setText("Scanning...")
        ida_kernwin.execute_sync(self._run_scan_code_strings, ida_kernwin.MFF_WRITE)

    def _run_scan_code_strings(self):
        results = []
        try:
            results = self.string_finder.find_all_encrypted_strings()
        except Exception as exc:
            idaapi.msg(f"[Sharingan] String scan failed: {exc}\n")
        self.btn_scan_code.setEnabled(True)
        self.btn_scan_code.setText("Scan code")
        self.populate_string_table(results)

    def populate_string_table(self, strings: list):
        self.string_results = strings or []
        count = len(self.string_results)
        self.lbl_string_count.setText(f"{count} string(s)")
        
        self.tbl_string.setUpdatesEnabled(False)
        self.tbl_string.clearContents()
        for row in range(self.tbl_string.rowCount()):
            self.tbl_string.setCellWidget(row, self.checkbox_header_index, None)
        if not self.string_results:
            self._initialize_string_table_placeholders()
            self.tbl_string.setUpdatesEnabled(True)
            self._position_checkbox_header_button()
            return

        self.tbl_string.setRowCount(count)
        self.string_row_checkboxes.clear()
        self._last_checkbox_row = None
        for row, item in enumerate(self.string_results):
            idx_item = self._make_table_item(str(row + 1), align=Qt.AlignCenter)
            raw_value = item.get("value", "")
            type_value = item.get("type", "")
            address = item.get("address", 0)
            preview_value = item.get("preview") or raw_value
            xref_list = item.get("xrefs") or []
            xref_text = f"({len(xref_list)} xrefs) {("\n".join(f"0x{ea:08X}" for ea in xref_list) if xref_list else "0")}"

            self.tbl_string.setItem(row, 1, idx_item)
            self.tbl_string.setItem(row, 2, self._make_table_item(raw_value, tooltip=raw_value))
            self.tbl_string.setItem(row, 3, self._make_table_item(f"0x{address:08X}", align=Qt.AlignCenter))
            self.tbl_string.setItem(row, 4, self._make_table_item(preview_value, tooltip=preview_value))
            self.tbl_string.setItem(row, 5, self._make_table_item(xref_text, tooltip=xref_text))
            self.tbl_string.setItem(row, 6, self._make_table_item(type_value, tooltip=type_value))
            self._add_checkbox_to_row(row)

        self.tbl_string.setUpdatesEnabled(True)
        self._update_checkbox_header_label()
        self._position_checkbox_header_button()


    def ignore_selected_strings(self):
        if not self.string_results:
            idaapi.msg("[Sharingan] No strings available to ignore.\n")
            return
        selected_rows = self.get_selected_string_rows()
        if not selected_rows:
            idaapi.msg("[Sharingan] Please select at least one string to ignore.\n")
            return
        values_to_ignore = []
        for row in selected_rows:
            item = self.tbl_string.item(row, 2)
            if item and item.text():
                values_to_ignore.append(item.text())
        if not values_to_ignore:
            idaapi.msg("[Sharingan] Unable to determine selected string values.\n")
            return
        if not self._append_ignore_strings(values_to_ignore):
            return
        selected_set = set(selected_rows)
        remaining_results = [
            entry
            for idx, entry in enumerate(self.string_results)
            if idx not in selected_set
        ]
        self.populate_string_table(remaining_results)
        idaapi.msg(f"[Sharingan] Ignored {len(values_to_ignore)} string(s).\n")

    def _append_ignore_strings(self, strings):
        store = getattr(self.string_finder, "ignore_store", None)
        if not store or not store.user_path:
            idaapi.msg("[Sharingan] Ignore store is unavailable.\n")
            return False
        new_literals = store.append_literals(strings)
        if not new_literals:
            idaapi.msg("[Sharingan] Selected strings already ignored.\n")
            return False
        self.string_finder.result_filter.ignore_literals.update(new_literals)
        return True

    def show_hex_values(self):
        """Toggle between text and hex display in Raw column."""
        self.show_hex_mode = not self.show_hex_mode
        self.btn_show_hex.setText("Show Text" if self.show_hex_mode else "Show Hex")
        
        for row in range(self.tbl_string.rowCount()):            
            entry = self.string_results[row]
            raw_value = entry.get("value", "") if isinstance(entry, dict) else ""
            
            if not raw_value:
                continue
            
            item = self.tbl_string.item(row, 2)
            if not item:
                continue
            
            if self.show_hex_mode:
                # Convert to hex
                try:
                    hex_value = raw_value.encode('utf-8', errors='replace').hex(' ').upper()
                    item.setText(hex_value)
                    item.setToolTip(f"Hex: {hex_value}\nOriginal: {raw_value}")
                except Exception as e:
                    idaapi.msg(f"[Sharingan] Error converting row {row + 1} to hex: {e}\n")
            else:
                # Show original text
                item.setText(raw_value)
                item.setToolTip(raw_value)

    # ------------------------------------------------------------------
    # Sorting by column header
    # ------------------------------------------------------------------
    def sort_by_column(self, column: int):
        """Sort table by clicked column header."""
        if column == 0:  # Skip checkbox column
            return
        
        # Toggle sort order if clicking same column
        if self.sort_column == column:
            self.sort_ascending = not self.sort_ascending
        else:
            self.sort_column = column
            self.sort_ascending = True
        
        if not self.string_results:
            return
        
        # Define sort keys for each column
        def sort_key(item):
            if column == 1:  # "#" - index
                return self.string_results.index(item)
            elif column == 2:  # "Raw" column 
                return item.get('value', '').lower()
            elif column == 3:  # "Address" column
                return item.get('address', 0)
            elif column == 4:  # "Preview" column
                return (item.get('preview') or item.get('value', '')).lower()
            elif column == 5:  # "Xref" column
                return item.get('xref_count', 0)
            elif column == 6:  # "Type" column
                return item.get('type', '').lower()
            return 0
        
        # Sort the data
        sorted_results = sorted(self.string_results, key=sort_key, reverse=not self.sort_ascending)
        
        # Repopulate table with sorted data
        self.populate_string_table(sorted_results)
