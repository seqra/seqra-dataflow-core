package org.seqra.dataflow.ap.ifds

import org.seqra.dataflow.ap.ifds.access.InitialFactAp

interface SideEffectKind

sealed interface SideEffectSummary {
    val kind: SideEffectKind

    data class ZeroSideEffectSummary(override val kind: SideEffectKind) : SideEffectSummary

    data class FactSideEffectSummary(val initialFactAp: InitialFactAp, override val kind: SideEffectKind) : SideEffectSummary
}
