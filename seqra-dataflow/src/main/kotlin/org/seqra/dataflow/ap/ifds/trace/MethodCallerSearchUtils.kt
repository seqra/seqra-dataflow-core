package org.seqra.dataflow.ap.ifds.trace

import org.seqra.dataflow.ap.ifds.MethodEntryPoint
import org.seqra.dataflow.ap.ifds.SummaryEdgeSubscriptionManager.MethodEntryPointCaller
import org.seqra.dataflow.ap.ifds.TaintAnalysisUnitRunner
import org.seqra.dataflow.ap.ifds.TaintAnalysisUnitRunnerManager

inline fun <T> TaintAnalysisUnitRunnerManager.withMethodRunner(
    methodEntryPoint: MethodEntryPoint,
    body: TaintAnalysisUnitRunner.() -> T,
): T {
    val unit = unitResolver.resolve(methodEntryPoint.method)
    val runner = findUnitRunner(unit) ?: error("No runner for unit: $unit")
    return runner.body()
}

fun TaintAnalysisUnitRunnerManager.findMethodCallers(methodEntryPoint: MethodEntryPoint): Set<MethodEntryPointCaller> {
    val result = hashSetOf<MethodEntryPointCaller>()

    withMethodRunner(methodEntryPoint) {
        methodCallers(methodEntryPoint, collectZeroCallsOnly = true, result)
    }

    val callers = methodCallers(methodEntryPoint.method)
    for (callerUnit in callers) {
        val runner = findUnitRunner(callerUnit) ?: error("No runner for unit: $callerUnit")
        runner.methodCallers(methodEntryPoint, collectZeroCallsOnly = true, result)
    }

    return result
}
