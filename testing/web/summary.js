function lsw_summary_graph_click_result(table_id, results_summary) {
    console.log("click-result", table_id, results_summary)
    // pass selection onto the table
    lsw_table_select_row("summary", results_summary)
}
