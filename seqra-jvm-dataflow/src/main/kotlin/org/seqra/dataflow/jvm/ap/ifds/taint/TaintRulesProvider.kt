package org.seqra.dataflow.jvm.ap.ifds.taint

import org.seqra.dataflow.ap.ifds.access.FactAp
import org.seqra.dataflow.ap.ifds.access.InitialFactAp
import org.seqra.ir.api.common.CommonMethod
import org.seqra.ir.api.common.cfg.CommonInst
import org.seqra.ir.api.jvm.JIRField
import org.seqra.dataflow.configuration.CommonTaintRulesProvider
import org.seqra.dataflow.configuration.jvm.TaintCleaner
import org.seqra.dataflow.configuration.jvm.TaintEntryPointSource
import org.seqra.dataflow.configuration.jvm.TaintMethodEntrySink
import org.seqra.dataflow.configuration.jvm.TaintMethodExitSink
import org.seqra.dataflow.configuration.jvm.TaintMethodExitSource
import org.seqra.dataflow.configuration.jvm.TaintMethodSink
import org.seqra.dataflow.configuration.jvm.TaintMethodSource
import org.seqra.dataflow.configuration.jvm.TaintPassThrough
import org.seqra.dataflow.configuration.jvm.TaintStaticFieldSource

interface TaintRulesProvider : CommonTaintRulesProvider {
    fun entryPointRulesForMethod(method: CommonMethod, fact: FactAp?, allRelevant: Boolean = false): Iterable<TaintEntryPointSource>
    fun sourceRulesForMethod(method: CommonMethod, statement: CommonInst, fact: FactAp?, allRelevant: Boolean = false): Iterable<TaintMethodSource>
    fun exitSourceRulesForMethod(method: CommonMethod, statement: CommonInst, fact: FactAp?, allRelevant: Boolean = false): Iterable<TaintMethodExitSource>
    fun sinkRulesForMethod(method: CommonMethod, statement: CommonInst, fact: FactAp?, allRelevant: Boolean = false): Iterable<TaintMethodSink>
    fun sinkRulesForMethodEntry(method: CommonMethod, fact: FactAp?, allRelevant: Boolean = false): Iterable<TaintMethodEntrySink>
    fun sinkRulesForMethodExit(method: CommonMethod, statement: CommonInst, fact: FactAp?, initialFacts: Set<InitialFactAp>?, allRelevant: Boolean = false): Iterable<TaintMethodExitSink>
    fun passTroughRulesForMethod(method: CommonMethod, statement: CommonInst, fact: FactAp?, allRelevant: Boolean = false): Iterable<TaintPassThrough>
    fun cleanerRulesForMethod(method: CommonMethod, statement: CommonInst, fact: FactAp?, allRelevant: Boolean = false): Iterable<TaintCleaner>
    fun sourceRulesForStaticField(field: JIRField, statement: CommonInst, fact: FactAp?, allRelevant: Boolean = false): Iterable<TaintStaticFieldSource>
}
