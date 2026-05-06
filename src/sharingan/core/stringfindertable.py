from typing import Any
import ida_kernwin
import idaapi
from PySide6.QtCore import Qt, QTimer, QItemSelectionModel
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
        self.last_checkbox_row = None
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
        self.tbl_string.setSelectionMode(QAbstractItemView.ExtendedSelection)
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
        self.tbl_string.customContextMenuRequested.connect(self.show_table_context_menu)
        self.tbl_string.horizontalScrollBar().valueChanged.connect(self._position_checkbox_header_button)

        layout.addWidget(self.tbl_string)
        self._initialize_string_table_placeholders()
        self._update_checkbox_header_label()
        QTimer.singleShot(0, self._position_checkbox_header_button)

    def _initialize_string_table_placeholders(self):
        self.tbl_string.setRowCount(1)
        self.tbl_string.clearContents()
        self.string_row_checkboxes.clear()
        self.last_checkbox_row = None
        for col in range(1, 7):
            align = Qt.AlignCenter if col in (1, 3) else None  # Center Index and Address
            tooltip = "0" if col == 2 else None
            self.tbl_string.setItem(0, col, self._make_table_item("0", align=align, tooltip=tooltip))
        self._add_checkbox_to_row(0, enabled=False, track=False)

    def _make_table_item(self, text: str, align: Qt.Alignment | None = None, tooltip: str | None = None):
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
            checkbox.stateChanged.connect(self._update_checkbox_header_label)
            checkbox.clicked.connect(lambda checked, r=row: self._handle_row_checkbox_clicked(r, checked))
        container = QWidget()
        layout = QHBoxLayout(container)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setAlignment(Qt.AlignCenter)
        layout.addWidget(checkbox)
        self.tbl_string.setCellWidget(row, self.checkbox_header_index, container)
        if enabled and track:
            self.string_row_checkboxes.append(checkbox)

    def _handle_row_checkbox_clicked(self, row: int, checked: bool):
        self.tbl_string.selectRow(row)
        modifiers = QApplication.keyboardModifiers()
        if modifiers & Qt.ShiftModifier and self.last_checkbox_row is not None:
            self._set_checkbox_range_state(self.last_checkbox_row, row, checked)
        self.last_checkbox_row = row

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

    def _handle_header_checkbox_button(self):
        select_all = not self._are_all_rows_checked()
        for cb in self.string_row_checkboxes:
            cb.blockSignals(True)
            cb.setChecked(select_all)
            cb.blockSignals(False)
        self.last_checkbox_row = None
        self._update_checkbox_header_label()

    def _update_checkbox_header_label(self):
        if not hasattr(self, "checkbox_header_button"):
            return
        self.checkbox_header_button.setText(
            "\u2611" if bool(self.string_row_checkboxes) and all(cb.isChecked() for cb in self.string_row_checkboxes) else "\u2610"
        )

    def _position_checkbox_header_button(self, *args):
        if  not self.checkbox_header_container:
            return
        header = self.tbl_string.horizontalHeader()
        if self.checkbox_header_index >= header.count():
            return
        x = header.sectionViewportPosition(self.checkbox_header_index)
        width = header.sectionSize(self.checkbox_header_index)
        self.checkbox_header_container.setGeometry(x, 0, width, header.height())
        self.checkbox_header_container.show()

    def show_table_context_menu(self, pos):
        index = self.tbl_string.indexAt(pos)
        if not index.isValid():
            return
        row = index.row()
        col = index.column()

        selection_model = self.tbl_string.selectionModel()
        if selection_model:
            if row not in {idx.row() for idx in selection_model.selectedRows()}:
                selection_model.select(index, QItemSelectionModel.SelectionFlag.Select | QItemSelectionModel.SelectionFlag.Rows)

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

        if self._selection_rows():
            menu.addSeparator()
            action_copy_rows = QAction("Copy Selected Rows", menu)
            action_copy_rows.triggered.connect(self._copy_selected_rows)
            menu.addAction(action_copy_rows)

        if menu.actions():
            menu.exec_(self.tbl_string.viewport().mapToGlobal(pos))

    # ------------------------------------------------------------------
    # Copy cell's value (Raw, Address, Preview, Xref, Type) to clipboard
    # ------------------------------------------------------------------
    def _copy_to_clipboard(self, row: int, field: str):
        entry = self.get_row(row)
        if entry is None:
            return
        raw = entry.get(field, "")
        QApplication.clipboard().setText(str(raw))

    # ------------------------------------------------------------------
    # Jump to the address of the selected string row
    # ------------------------------------------------------------------
    def _jump_to_address(self, row: int):
        entry = self.string_results[row]
        address = entry.get("address") if isinstance(entry, dict) else entry
        idaapi.jumpto(address)
    
    # ------------------------------------------------------------------
    # Print xrefs of string for further checking.
    # ------------------------------------------------------------------
    def _print_xrefs(self, row: int):
        entry = self.get_row(row)
        raw_xrefs = entry.get("xrefs") or []
        if not raw_xrefs:
            print("[Sharingan] No xrefs recorded for the selected string.\n")
            return
        xrefs_str = ", ".join(f"0x{ea:08X}" for ea in raw_xrefs)
        print(f"[Sharingan] Xrefs for row {row + 1}: {xrefs_str}\n")

    # ------------------------------------------------------------------
    # Copy all selected rows (highlighted rows) as a table for outer using.
    # ------------------------------------------------------------------
    def _copy_selected_rows(self):
        rows = self._selection_rows()
        if not rows or not self.string_results:
            return
        headers = ["#", "Raw", "Address", "Preview", "Xref", "Type"]
        lines = ["\t".join(headers)]
        for row in rows:
            entry = self.string_results[row]
            raw_value = str(entry.get("value", ""))
            address = entry.get("address", 0)
            preview_value = self.tbl_string.item(row, 4).text()
            xrefs = entry.get("xrefs") or []
            xref_text = f"{len(xrefs)}"
            type_value = str(entry.get("type", ""))
            lines.append(
                "\t".join(
                    [
                        str(row + 1),
                        raw_value,
                        f"0x{address:08X}",
                        preview_value,
                        xref_text,
                        type_value,
                    ]
                )
            )
        if len(lines) > 1:
            QApplication.clipboard().setText("\n".join(lines))

    # ------------------------------------------------------------------
    # Retrieve selected string rows (highlighted rows)
    # ------------------------------------------------------------------
    def _selection_rows(self):
        selection_model = self.tbl_string.selectionModel()
        if not selection_model:
            return []
        return sorted({idx.row() for idx in selection_model.selectedRows()})

    # ------------------------------------------------------------------
    # Get row by index
    # ------------------------------------------------------------------
    def get_row(self, idx: int):
        if 0 <= idx < len(self.string_results):
            return self.string_results[idx]
        return None

    # ------------------------------------------------------------------
    # Get snapshot of string table for little used feature
    # ------------------------------------------------------------------
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

    # ------------------------------------------------------------------
    # Apply decryption results to preview of checked string rows
    # ------------------------------------------------------------------
    def update_preview(self, row_idx, preview_value):
        entry = self.get_row(row_idx)
        if entry is None:
            return False

        if isinstance(entry, dict):
            entry["preview"] = preview_value

        text = str(preview_value)
        table_item = self.tbl_string.item(row_idx, 4)
        if table_item:
            table_item.setText(text)
            table_item.setToolTip(text)
        else:
            self.tbl_string.setItem(row_idx, 4, self._make_table_item(text, tooltip=text))
        return True

    # ------------------------------------------------------------------
    # Scan code strings
    # Trigger to scan all code sections for potentially encrypted strings 
    # from static strings, stack strings, and tight strings,
    # ------------------------------------------------------------------
    def scan_code_strings(self):
        if self.string_finder is None:
            print("[Sharingan] String Finder modules unavailable.\n")
            return
        self.btn_scan_code.setEnabled(False)
        self.btn_scan_code.setText("Scanning...")
        ida_kernwin.execute_sync(self._run_scan_code_strings, ida_kernwin.MFF_WRITE)

    def _run_scan_code_strings(self):
        results = []
        try:
            results = self.string_finder.find_all_encrypted_strings()
        except Exception as exc:
            print(f"[Sharingan] String scan failed: {exc}\n")
        self.btn_scan_code.setEnabled(True)
        self.btn_scan_code.setText("Scan code")
        self.populate_string_table(results)

    # ------------------------------------------------------------------
    # Filling string table with results
    # ------------------------------------------------------------------
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
        self.last_checkbox_row = None
        for row, item in enumerate(self.string_results):
            idx_item = self._make_table_item(str(row + 1), align=Qt.AlignCenter)
            raw_value = item.get("value", "")
            type_value = item.get("type", "")
            address = item.get("address", 0)
            preview_value = item.get("preview") or raw_value
            xref_list = item.get("xrefs") or []
            xrefs_joined = "\n".join(f"0x{ea:08X}" for ea in xref_list) if xref_list else "0"
            xref_text = f"({len(xref_list)} xrefs) {xrefs_joined}"

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

    # ------------------------------------------------------------------
    # Retrieve all checked string box
    # ------------------------------------------------------------------
    def get_checked_box_rows(self):
        selected_rows = []
        for idx, checkbox in enumerate(self.string_row_checkboxes):
            if checkbox.isEnabled() and checkbox.isChecked():
                selected_rows.append(idx)
        return selected_rows

    # ------------------------------------------------------------------
    # Ignore checked string box, 
    # saved them into User Roaming Directory then try to copy into bundle ignore_string in ida plugin directory
    # ------------------------------------------------------------------
    def ignore_selected_strings(self):
        if not self.string_results:
            print("[Sharingan] No strings available to ignore.\n")
            return

        selected_rows = self.get_checked_box_rows()
        if not selected_rows:
            print("[Sharingan] Please select at least one string to ignore.\n")
            return

        values_to_ignore = []
        for row in selected_rows:
            item = self.tbl_string.item(row, 2)
            if item and item.text():
                values_to_ignore.append(item.text())

        if not values_to_ignore:
            print("[Sharingan] Unable to determine selected string values.\n")
            return

        if not self._append_ignore_strings(values_to_ignore):
            return
        
        selected_set = set(selected_rows)
        remaining_results = [ entry for idx, entry in enumerate(self.string_results) if idx not in selected_set ]
        self.populate_string_table(remaining_results)
        print(f"[Sharingan] Ignored {len(values_to_ignore)} string(s).\n")

    def _append_ignore_strings(self, strings):
        store = getattr(self.string_finder, "ignore_store", None)
        if not store or not store.user_path:
            print("[Sharingan] Ignore store is unavailable.\n")
            return False
        new_literals = store.append_literals(strings)
        if not new_literals:
            print("[Sharingan] Selected strings already ignored.\n")
            return False
        self.string_finder.result_filter.ignore_literals.update(new_literals)
        return True

    # ------------------------------------------------------------------
    # Show hex values in Raw column
    # ------------------------------------------------------------------
    def show_hex_values(self):
        """Toggle between text and hex display in Raw column."""
        self.show_hex_mode = not self.show_hex_mode
        self.btn_show_hex.setText("Show Text" if self.show_hex_mode else "Show Hex")

        if len(self.string_results) == 0:
            return

        for row in range(self.tbl_string.rowCount()):
            entry = self.string_results[row]
            raw_value = entry.get("value", "") if isinstance(entry, dict) else ""

            item = self.tbl_string.item(row, 2)
            if not item:
                continue

            if self.show_hex_mode:
                # Convert to hex
                try:
                    hex_value = raw_value.encode('utf-8', errors='replace').hex().upper()
                    item.setText(hex_value)
                    item.setToolTip(f"Hex: {hex_value}\nOriginal: {raw_value}")
                except Exception as e:
                    print(f"[Sharingan] Error converting row {row + 1} to hex: {e}\n")
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
