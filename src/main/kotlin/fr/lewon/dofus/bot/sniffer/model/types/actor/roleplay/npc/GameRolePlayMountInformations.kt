package fr.lewon.dofus.bot.sniffer.model.types.actor.roleplay.npc

import fr.lewon.dofus.bot.core.io.stream.ByteArrayReader
import fr.lewon.dofus.bot.sniffer.model.types.actor.roleplay.GameRolePlayNamedActorInformations

class GameRolePlayMountInformations : GameRolePlayNamedActorInformations() {

    lateinit var ownerName: String
    var level = -1

    override fun deserialize(stream: ByteArrayReader) {
        super.deserialize(stream)
        ownerName = stream.readUTF()
        level = stream.readUnsignedByte()
    }
}