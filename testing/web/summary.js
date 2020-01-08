function lsw_summary_graph_click_test_run(table_id, test_run) {
    // pass selection onto the table
    lsw_table_select_rows("summary", new Set([test_run]))
}
