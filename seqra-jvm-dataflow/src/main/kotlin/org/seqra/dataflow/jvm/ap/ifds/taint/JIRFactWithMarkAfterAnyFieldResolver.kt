package org.seqra.dataflow.jvm.ap.ifds.taint

import org.seqra.dataflow.ap.ifds.MethodEntryPoint
import org.seqra.dataflow.ap.ifds.SideEffectKind
import org.seqra.dataflow.ap.ifds.TaintMarkAccessor
import org.seqra.dataflow.ap.ifds.access.InitialFactAp

data class TaintMarkFieldUnfoldRequest(
    val method: MethodEntryPoint,
    val fact: InitialFactAp,
    val mark: TaintMarkAccessor
) : SideEffectKind

data class JIRFactWithMarkAfterAnyFieldResolver(
    private val method: MethodEntryPoint,
    private val initialFact: InitialFactAp,
    private val addSideEffect: (InitialFactAp, SideEffectKind) -> Unit
) {
    fun resolve(mark: TaintMarkAccessor) {
        addSideEffect(initialFact, TaintMarkFieldUnfoldRequest(method, initialFact, mark))
    }

    companion object {
        fun createMarkAfterFieldsResolver(
            method: MethodEntryPoint,
            initialFacts: Set<InitialFactAp>,
            addSideEffect: (InitialFactAp, SideEffectKind) -> Unit
        ): JIRFactWithMarkAfterAnyFieldResolver? {
            // 0 or 2+ facts implies that we have no abstraction
            if (initialFacts.size != 1) return null
            return JIRFactWithMarkAfterAnyFieldResolver(method, initialFacts.first(), addSideEffect)
        }
    }
}
