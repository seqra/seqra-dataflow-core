package org.seqra.dataflow.ap.ifds

import org.seqra.dataflow.ap.ifds.analysis.AnalysisManager
import org.seqra.dataflow.ap.ifds.analysis.MethodAnalysisContext
import org.seqra.dataflow.ap.ifds.analysis.MethodCallResolver
import org.seqra.dataflow.ap.ifds.taint.TaintAnalysisContext
import org.seqra.ir.api.common.CommonMethod
import org.seqra.ir.api.common.cfg.CommonInst
import org.seqra.util.analysis.ApplicationGraph

interface TaintAnalysisManager : AnalysisManager {
    override fun getMethodAnalysisContext(
        methodEntryPoint: MethodEntryPoint,
        graph: ApplicationGraph<CommonMethod, CommonInst>,
        callResolver: MethodCallResolver,
    ): MethodAnalysisContext {
        error("Taint context required")
    }

    fun getMethodAnalysisContext(
        methodEntryPoint: MethodEntryPoint,
        graph: ApplicationGraph<CommonMethod, CommonInst>,
        callResolver: MethodCallResolver,
        taintAnalysisContext: TaintAnalysisContext,
    ): MethodAnalysisContext
}
