package org.seqra.dataflow.ap.ifds.analysis

import org.seqra.dataflow.ap.ifds.AccessPathBase
import org.seqra.dataflow.ap.ifds.SideEffectKind
import org.seqra.dataflow.ap.ifds.access.FinalFactAp
import org.seqra.dataflow.ap.ifds.access.InitialFactAp
import org.seqra.dataflow.configuration.CommonTaintAction
import org.seqra.dataflow.configuration.CommonTaintConfigurationItem

interface MethodCallFlowFunction {
    sealed interface CallFact

    sealed interface Call2ReturnFact

    sealed interface ZeroCallFact: CallFact

    sealed interface FactCallFact: CallFact

    sealed interface NDFactCallFact: CallFact

    data object Unchanged : ZeroCallFact, FactCallFact, NDFactCallFact

    data object CallToReturnZeroFact: ZeroCallFact, Call2ReturnFact

    data object CallToStartZeroFact : ZeroCallFact

    data class CallToReturnFFact(
        val initialFactAp: InitialFactAp,
        val factAp: FinalFactAp,
        val traceInfo: TraceInfo?,
    ) : FactCallFact, ZeroCallFact, Call2ReturnFact

    data class CallToStartFFact(
        val initialFactAp: InitialFactAp,
        val callerFactAp: FinalFactAp,
        val startFactBase: AccessPathBase,
        val traceInfo: TraceInfo?,
    ) : FactCallFact

    data class CallToReturnZFact(
        val factAp: FinalFactAp,
        val traceInfo: TraceInfo?,
    ) : ZeroCallFact, FactCallFact, NDFactCallFact, Call2ReturnFact

    data class CallToStartZFact(
        val callerFactAp: FinalFactAp,
        val startFactBase: AccessPathBase,
        val traceInfo: TraceInfo?,
    ) : ZeroCallFact

    data class CallToReturnNonDistributiveFact(
        val initialFacts: Set<InitialFactAp>,
        val factAp: FinalFactAp,
        val traceInfo: TraceInfo?,
    ) : FactCallFact, ZeroCallFact, NDFactCallFact, Call2ReturnFact

    data class CallToStartNDFFact(
        val initialFacts: Set<InitialFactAp>,
        val callerFactAp: FinalFactAp,
        val startFactBase: AccessPathBase,
        val traceInfo: TraceInfo?,
    ) : NDFactCallFact

    data class SideEffectRequirement(val initialFactAp: InitialFactAp) : FactCallFact

    data class ZeroSideEffect(val kind: SideEffectKind) : ZeroCallFact
    data class FactSideEffect(val initialFactAp: InitialFactAp, val kind: SideEffectKind) : FactCallFact

    data class Drop(
        val traceInfo: TraceInfo?,
    ) : ZeroCallFact, FactCallFact, NDFactCallFact, Call2ReturnFact

    sealed interface TraceInfo {
        data object Flow : TraceInfo
        data class Rule(val rule: CommonTaintConfigurationItem, val action: CommonTaintAction): TraceInfo
    }

    fun propagateZeroToZero(): Set<ZeroCallFact>
    fun propagateZeroToFact(currentFactAp: FinalFactAp): Set<ZeroCallFact>
    fun propagateFactToFact(initialFactAp: InitialFactAp, currentFactAp: FinalFactAp): Set<FactCallFact>
    fun propagateNDFactToFact(initialFacts: Set<InitialFactAp>, currentFactAp: FinalFactAp): Set<NDFactCallFact>
}
