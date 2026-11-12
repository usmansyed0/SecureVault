package com.securevault.database

import androidx.sqlite.db.SupportSQLiteDatabase
import org.junit.Assert.assertEquals
import org.junit.Test
import org.mockito.kotlin.argumentCaptor
import org.mockito.kotlin.atLeastOnce
import org.mockito.kotlin.mock
import org.mockito.kotlin.verify

class RoomMigrationTest {

    @Test
    fun migration1To2_executesExpectedSchemaStatements() {
        val db: SupportSQLiteDatabase = mock()
        val captor = argumentCaptor<String>()

        assertEquals(1, LocalDatabase.MIGRATION_1_2.startVersion)
        assertEquals(2, LocalDatabase.MIGRATION_1_2.endVersion)

        LocalDatabase.MIGRATION_1_2.migrate(db)

        verify(db, atLeastOnce()).execSQL(captor.capture())
        val sqls = captor.allValues

        assert(sqls.any { it.contains("ALTER TABLE vault_records ADD COLUMN vaultId") })
        assert(sqls.any { it.contains("ALTER TABLE vault_records ADD COLUMN type") })
        assert(sqls.any { it.contains("ALTER TABLE vault_records ADD COLUMN formatVersion") })
        assert(sqls.any { it.contains("ALTER TABLE vault_records ADD COLUMN wrappedDek") })
        assert(sqls.any { it.contains("ALTER TABLE vault_records ADD COLUMN wrappedDekNonce") })
        assert(sqls.any { it.contains("ALTER TABLE vault_records ADD COLUMN deleted") })
    }

    @Test
    fun migration2To3_executesExpectedSchemaStatements() {
        val db: SupportSQLiteDatabase = mock()
        val captor = argumentCaptor<String>()

        assertEquals(2, LocalDatabase.MIGRATION_2_3.startVersion)
        assertEquals(3, LocalDatabase.MIGRATION_2_3.endVersion)

        LocalDatabase.MIGRATION_2_3.migrate(db)

        verify(db, atLeastOnce()).execSQL(captor.capture())
        val sqls = captor.allValues

        assert(sqls.any { it.contains("ALTER TABLE vault_records ADD COLUMN clientRevision") })
        assert(sqls.any { it.contains("ALTER TABLE vault_records ADD COLUMN serverSeq") })
        assert(sqls.any { it.contains("ALTER TABLE vault_records ADD COLUMN pendingSync") })
        assert(sqls.any { it.contains("CREATE TABLE IF NOT EXISTS sync_queue") })
        assert(sqls.any { it.contains("CREATE TABLE IF NOT EXISTS sync_metadata") })
    }
}
