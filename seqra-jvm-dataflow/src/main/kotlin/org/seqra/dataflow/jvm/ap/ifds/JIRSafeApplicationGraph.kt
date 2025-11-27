package org.seqra.dataflow.jvm.ap.ifds

import mu.KLogging
import org.seqra.ir.api.jvm.JIRMethod
import org.seqra.ir.api.jvm.cfg.JIRInst
import org.seqra.jvm.graph.JApplicationGraph
import org.seqra.util.analysis.ApplicationGraph

class JIRSafeApplicationGraph(
    private val graph: JApplicationGraph
) : JApplicationGraph by graph {
    class SafeMethodGraph(
        private val graph: ApplicationGraph.MethodGraph<JIRMethod, JIRInst>
    ) : ApplicationGraph.MethodGraph<JIRMethod, JIRInst> by graph {
        override fun entryPoints(): Sequence<JIRInst> = try {
            graph.entryPoints()
        } catch (e: Throwable) {
            logger.error(e) { "Method inst list failure $method" }
            // we couldn't find instructions list
            // TODO: maybe fix flowGraph()
            emptySequence()
        }

        override fun exitPoints(): Sequence<JIRInst> = try {
            graph.exitPoints()
        } catch (e: Throwable) {
            logger.error(e) { "Method inst list failure $method" }
            // we couldn't find instructions list
            // TODO: maybe fix flowGraph()
            emptySequence()
        }
    }

    override fun methodGraph(method: JIRMethod) = SafeMethodGraph(graph.methodGraph(method))

    companion object {
        private val logger = object : KLogging() {}.logger
    }
}
