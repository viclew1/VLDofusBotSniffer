package fr.lewon.dofus.bot.sniffer.model.types.actor.roleplay.monster

import fr.lewon.dofus.bot.core.io.stream.BooleanByteWrapper
import fr.lewon.dofus.bot.core.io.stream.ByteArrayReader
import fr.lewon.dofus.bot.sniffer.model.TypeManager
import fr.lewon.dofus.bot.sniffer.model.types.actor.roleplay.GameRolePlayActorInformations

open class GameRolePlayGroupMonsterInformations : GameRolePlayActorInformations() {

    var keyRingBonus = false
    var hasHardcoreDrop = false
    var hasAVARewardToken = false
    lateinit var staticInfos: GroupMonsterStaticInformations
    var lootShare = -1
    var alignmentSide = -1

    override fun deserialize(stream: ByteArrayReader) {
        super.deserialize(stream)
        val box = stream.readByte()
        keyRingBonus = BooleanByteWrapper.getFlag(box, 0)
        hasHardcoreDrop = BooleanByteWrapper.getFlag(box, 1)
        hasAVARewardToken = BooleanByteWrapper.getFlag(box, 2)
        staticInfos = TypeManager.getInstance(stream.readUnsignedShort())
        staticInfos.deserialize(stream)
        lootShare = stream.readByte().toInt()
        alignmentSide = stream.readByte().toInt()
    }
}