package org.seqra.dataflow.ap.ifds.access.tree

import org.seqra.dataflow.ap.ifds.AccessPathBase
import org.seqra.dataflow.ap.ifds.ExclusionSet
import org.seqra.dataflow.ap.ifds.access.FinalFactAp
import org.seqra.dataflow.ap.ifds.access.common.FinalApAccess

interface TreeFinalApAccess: FinalApAccess<AccessTree.AccessNode> {
    val apManager: TreeApManager

    override fun getFinalAccess(factAp: FinalFactAp): AccessTree.AccessNode =
        (factAp as AccessTree).access

    override fun createFinal(base: AccessPathBase, ap: AccessTree.AccessNode, ex: ExclusionSet): FinalFactAp =
        AccessTree(apManager, base, ap, ex)
}
