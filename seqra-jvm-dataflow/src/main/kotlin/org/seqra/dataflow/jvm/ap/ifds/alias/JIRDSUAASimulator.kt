package org.seqra.dataflow.jvm.ap.ifds.alias

import it.unimi.dsi.fastutil.ints.Int2ObjectMap
import org.seqra.dataflow.graph.simulateGraph
import org.seqra.ir.api.jvm.cfg.JIRInst

inline fun <reified State : Any> simulateJIG(
    jig: JIRIntraProcAliasAnalysis.JIRInstGraph,
    initialState: State,
    statesBefore: Array<State?>,
    eval: (JIRInst, State) -> State,
    merge: (Int2ObjectMap<State?>) -> State,
) = simulateGraph(
    graph = jig.graph,
    initialStmtIdx = jig.initialIdx,
    initialState = initialState,
    merge = { _, states ->
        merge(states)
    },
    eval = { idx, state ->
        statesBefore[idx] = state
        val inst = jig.statements[idx]
        eval(inst, state)
    },
)
