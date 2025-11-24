package org.seqra.dataflow.ap.ifds.analysis

import org.seqra.dataflow.ap.ifds.ExclusionSet
import org.seqra.dataflow.ap.ifds.MethodSummaryEdgeApplicationUtils.SummaryEdgeApplication
import org.seqra.dataflow.ap.ifds.MethodSummaryEdgeApplicationUtils.SummaryEdgeApplication.SummaryApRefinement
import org.seqra.dataflow.ap.ifds.MethodSummaryEdgeApplicationUtils.SummaryEdgeApplication.SummaryExclusionRefinement
import org.seqra.dataflow.ap.ifds.SideEffectKind
import org.seqra.dataflow.ap.ifds.SideEffectSummary
import org.seqra.dataflow.ap.ifds.access.FinalFactAp
import org.seqra.dataflow.ap.ifds.access.InitialFactAp
import org.seqra.dataflow.ap.ifds.analysis.MethodSequentFlowFunction.Sequent

interface MethodSideEffectSummaryHandler {
    fun handleZeroToZero(
        sideEffects: List<SideEffectSummary.ZeroSideEffectSummary>,
    ): Set<Sequent> = emptySet()

    fun handleZeroToFact(
        currentFactAp: FinalFactAp,
        summaryEffect: SummaryEdgeApplication,
        kind: SideEffectKind
    ): Set<Sequent> = handleSummary(summaryEffect, kind) { _, k ->
        Sequent.ZeroSideEffect(k)
    }

    fun handleFactToFact(
        currentInitialFactAp: InitialFactAp,
        currentFactAp: FinalFactAp,
        summaryEffect: SummaryEdgeApplication,
        kind: SideEffectKind
    ): Set<Sequent> = handleSummary(summaryEffect, kind) { ex, k ->
        Sequent.FactSideEffect(currentInitialFactAp.replaceExclusions(ex), k)
    }

    fun handleSummary(
        summaryEffect: SummaryEdgeApplication,
        kind: SideEffectKind,
        handleSE: (initialFactRefinement: ExclusionSet, kind: SideEffectKind) -> Sequent
    ): Set<Sequent> = when (summaryEffect) {
        // Side effect requires more concrete fact
        is SummaryApRefinement -> emptySet()

        is SummaryExclusionRefinement -> {
            setOf(handleSE(summaryEffect.exclusion, kind))
        }
    }
}
