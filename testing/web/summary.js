function lsw_summary_graph_click_test_run(table_id, test_runs_summary) {
    console.log("click-test_run", table_id, test_runs_summary)
    // pass selection onto the table
    lsw_table_select_row("summary", test_runs_summary)
}
