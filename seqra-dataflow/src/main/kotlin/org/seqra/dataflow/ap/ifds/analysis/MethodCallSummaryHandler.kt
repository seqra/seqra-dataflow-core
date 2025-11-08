package org.seqra.dataflow.ap.ifds.analysis

import org.seqra.dataflow.ap.ifds.Edge
import org.seqra.dataflow.ap.ifds.ExclusionSet
import org.seqra.dataflow.ap.ifds.FactTypeChecker
import org.seqra.dataflow.ap.ifds.MethodSummaryEdgeApplicationUtils.SummaryEdgeApplication
import org.seqra.dataflow.ap.ifds.MethodSummaryEdgeApplicationUtils.SummaryEdgeApplication.SummaryApRefinement
import org.seqra.dataflow.ap.ifds.MethodSummaryEdgeApplicationUtils.SummaryEdgeApplication.SummaryExclusionRefinement
import org.seqra.dataflow.ap.ifds.access.FinalFactAp
import org.seqra.dataflow.ap.ifds.access.InitialFactAp
import org.seqra.dataflow.ap.ifds.analysis.MethodSequentFlowFunction.Sequent
import org.seqra.dataflow.ap.ifds.analysis.MethodSequentFlowFunction.TraceInfo

interface MethodCallSummaryHandler {
    val factTypeChecker: FactTypeChecker

    fun mapMethodExitToReturnFlowFact(fact: FinalFactAp): List<FinalFactAp>

    fun handleZeroToZero(summaryFact: FinalFactAp?): Set<Sequent> {
        if (summaryFact == null) return setOf(Sequent.ZeroToZero)

        val summaryExitFacts = mapMethodExitToReturnFlowFact(summaryFact)
        return summaryExitFacts.mapTo(hashSetOf()) {
            Sequent.ZeroToFact(it, TraceInfo.ApplySummary)
        }
    }

    fun handleZeroToFact(
        currentFactAp: FinalFactAp,
        summaryEffect: SummaryEdgeApplication,
        summaryFact: FinalFactAp
    ): Set<Sequent> = handleSummary(
        currentFactAp,
        summaryEffect,
        summaryFact,
        createSideEffectRequirement = {
            check(it is ExclusionSet.Universe) { "Incorrect refinement" }
            null
        }
    ) { initialFactRefinement: ExclusionSet?, summaryFactAp ->
        check(initialFactRefinement == null || initialFactRefinement is ExclusionSet.Universe) {
            "Incorrect refinement"
        }

        Sequent.ZeroToFact(summaryFactAp, TraceInfo.ApplySummary)
    }

    fun handleFactToFact(
        initialFactAp: InitialFactAp,
        currentFactAp: FinalFactAp,
        summaryEffect: SummaryEdgeApplication,
        summaryFact: FinalFactAp
    ): Set<Sequent> = handleSummary(
        currentFactAp,
        summaryEffect,
        summaryFact,
        createSideEffectRequirement = { refinement ->
            Sequent.SideEffectRequirement(initialFactAp.refine(refinement))
        }
    ) { initialFactRefinement: ExclusionSet?, summaryFactAp: FinalFactAp ->
        Sequent.FactToFact(initialFactAp.refine(initialFactRefinement), summaryFactAp, TraceInfo.ApplySummary)
    }

    fun prepareFactToFactSummary(summaryEdge: Edge.FactToFact): Edge.FactToFact? = summaryEdge

    fun handleNDFactToFact(
        initialFacts: Set<InitialFactAp>,
        currentFactAp: FinalFactAp,
        summaryEffect: SummaryEdgeApplication,
        summaryFact: FinalFactAp
    ): Set<Sequent> = handleSummary(
        currentFactAp,
        summaryEffect,
        summaryFact,
        createSideEffectRequirement = {
            check(it is ExclusionSet.Universe) { "Incorrect refinement" }
            null
        }
    ) { initialFactRefinement: ExclusionSet?, summaryFactAp: FinalFactAp ->
        check(initialFactRefinement == null || initialFactRefinement is ExclusionSet.Universe) {
            "Incorrect refinement"
        }

        Sequent.NDFactToFact(
            initialFacts.mapTo(hashSetOf()) { it.refine(initialFactRefinement) },
            summaryFactAp,
            TraceInfo.ApplySummary
        )
    }

    fun prepareNDFactToFactSummary(summaryEdge: Edge.NDFactToFact): Edge.NDFactToFact? = summaryEdge

    fun InitialFactAp.refine(exclusionSet: ExclusionSet?) =
        if (exclusionSet == null) this else replaceExclusions(exclusionSet)

    fun handleSummary(
        currentFactAp: FinalFactAp,
        summaryEffect: SummaryEdgeApplication,
        summaryFact: FinalFactAp,
        createSideEffectRequirement: (refinement: ExclusionSet) -> Sequent?,
        handleSummaryEdge: (initialFactRefinement: ExclusionSet?, summaryFactAp: FinalFactAp) -> Sequent
    ): Set<Sequent> {
        val mappedSummaryFacts = mapMethodExitToReturnFlowFact(summaryFact)

        return when (summaryEffect) {
            is SummaryApRefinement -> mappedSummaryFacts.mapNotNullTo(hashSetOf()) { mappedSummaryFact ->
                // todo: filter exclusions
                val summaryFactAp = mappedSummaryFact
                    .concat(factTypeChecker, summaryEffect.delta)
                    ?.replaceExclusions(currentFactAp.exclusions)
                    ?: return@mapNotNullTo null

                handleSummaryEdge(null, summaryFactAp)
            }

            is SummaryExclusionRefinement -> mappedSummaryFacts.mapTo(hashSetOf()) { mappedSummaryFact ->
                // todo: filter exclusions
                val summaryFactAp = mappedSummaryFact.replaceExclusions(summaryEffect.exclusion)

                handleSummaryEdge(summaryEffect.exclusion, summaryFactAp)
            }
        }
    }
}
