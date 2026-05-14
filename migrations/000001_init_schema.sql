-- +goose Up
-- +goose StatementBegin

-- users хранит учетные записи пользователей
-- В таблице не хранится пароль в открытом виде, только результат password hashing
CREATE TABLE users (
    id UUID PRIMARY KEY,
    login TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE users IS 'Учетные записи пользователей GophKeeper';
COMMENT ON COLUMN users.id IS 'Уникальный идентификатор пользователя';
COMMENT ON COLUMN users.login IS 'Уникальный логин пользователя для входа';
COMMENT ON COLUMN users.password_hash IS 'Хеш пароля входа, открытый пароль не хранится';
COMMENT ON COLUMN users.created_at IS 'Дата и время создания пользователя на сервере';
COMMENT ON COLUMN users.updated_at IS 'Дата и время последнего обновления пользователя на сервере';

-- user_vaults хранит зашифрованный ключ пользовательского хранилища
-- Сервер не знает мастер-пароль, key-encryption key и vault key в открытом виде
-- На MVP у пользователя один vault, поэтому user_id используется как primary key
CREATE TABLE user_vaults (
    user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    encrypted_vault_key BYTEA NOT NULL,
    vault_key_nonce BYTEA NOT NULL,
    vault_key_encryption_alg TEXT NOT NULL,
    kdf_alg TEXT NOT NULL,
    kdf_salt BYTEA NOT NULL,
    kdf_time_cost INTEGER NOT NULL,
    kdf_memory_kib INTEGER NOT NULL,
    kdf_parallelism INTEGER NOT NULL,
    kdf_key_length INTEGER NOT NULL,
    encrypted_metadata BYTEA,
    metadata_nonce BYTEA,
    metadata_encryption_alg TEXT,
    version BIGINT NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE user_vaults IS 'Зашифрованное хранилище пользователя и параметры получения ключа из мастер-пароля';
COMMENT ON COLUMN user_vaults.user_id IS 'Идентификатор владельца vault, также primary key для связи один пользователь к одному vault';
COMMENT ON COLUMN user_vaults.encrypted_vault_key IS 'Vault key, зашифрованный на клиенте ключом, полученным из мастер-пароля';
COMMENT ON COLUMN user_vaults.vault_key_nonce IS 'Nonce для расшифровки encrypted_vault_key на клиенте';
COMMENT ON COLUMN user_vaults.vault_key_encryption_alg IS 'Алгоритм шифрования encrypted_vault_key';
COMMENT ON COLUMN user_vaults.kdf_alg IS 'Алгоритм KDF для получения key-encryption key из мастер-пароля';
COMMENT ON COLUMN user_vaults.kdf_salt IS 'Соль KDF для мастер-пароля';
COMMENT ON COLUMN user_vaults.kdf_time_cost IS 'Вычислительная стоимость KDF';
COMMENT ON COLUMN user_vaults.kdf_memory_kib IS 'Объем памяти KDF в KiB';
COMMENT ON COLUMN user_vaults.kdf_parallelism IS 'Уровень параллелизма KDF';
COMMENT ON COLUMN user_vaults.kdf_key_length IS 'Длина ключа, который получается через KDF';
COMMENT ON COLUMN user_vaults.encrypted_metadata IS 'Зашифрованная метаинформация vault, например клиентская версия схемы';
COMMENT ON COLUMN user_vaults.metadata_nonce IS 'Nonce для расшифровки encrypted_metadata';
COMMENT ON COLUMN user_vaults.metadata_encryption_alg IS 'Алгоритм шифрования encrypted_metadata';
COMMENT ON COLUMN user_vaults.version IS 'Версия vault для оптимистичной блокировки будущих обновлений';
COMMENT ON COLUMN user_vaults.created_at IS 'Дата и время создания vault на сервере';
COMMENT ON COLUMN user_vaults.updated_at IS 'Дата и время последнего обновления vault на сервере';

-- vault_items хранит зашифрованные пользовательские секреты
-- metadata и payload должны приходить на сервер уже зашифрованными на клиенте
-- deleted_at используется для soft delete и синхронизации tombstones между устройствами
CREATE TABLE vault_items (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    type TEXT NOT NULL,
    encrypted_metadata BYTEA NOT NULL,
    metadata_nonce BYTEA NOT NULL,
    encrypted_payload BYTEA NOT NULL,
    payload_nonce BYTEA NOT NULL,
    encryption_alg TEXT NOT NULL,
    payload_schema_version INTEGER NOT NULL,
    version BIGINT NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ
);

COMMENT ON TABLE vault_items IS 'Зашифрованные элементы пользовательского хранилища';
COMMENT ON COLUMN vault_items.id IS 'Уникальный идентификатор элемента хранилища';
COMMENT ON COLUMN vault_items.user_id IS 'Идентификатор владельца элемента хранилища';
COMMENT ON COLUMN vault_items.type IS 'Тип секрета из proto enum ItemType в строковом представлении';
COMMENT ON COLUMN vault_items.encrypted_metadata IS 'Зашифрованная метаинформация элемента, например сайт, банк, название или описание';
COMMENT ON COLUMN vault_items.metadata_nonce IS 'Nonce для расшифровки encrypted_metadata на клиенте';
COMMENT ON COLUMN vault_items.encrypted_payload IS 'Зашифрованное содержимое секрета';
COMMENT ON COLUMN vault_items.payload_nonce IS 'Nonce для расшифровки encrypted_payload на клиенте';
COMMENT ON COLUMN vault_items.encryption_alg IS 'Алгоритм шифрования metadata и payload';
COMMENT ON COLUMN vault_items.payload_schema_version IS 'Версия клиентской схемы encrypted_payload';
COMMENT ON COLUMN vault_items.version IS 'Версия элемента для optimistic concurrency control';
COMMENT ON COLUMN vault_items.created_at IS 'Дата и время создания элемента на сервере';
COMMENT ON COLUMN vault_items.updated_at IS 'Дата и время последнего обновления элемента на сервере';
COMMENT ON COLUMN vault_items.deleted_at IS 'Дата и время soft delete, NULL означает что элемент активен';

-- Индекс для всех запросов, которые выбирают элементы конкретного пользователя
CREATE INDEX idx_vault_items_user_id
    ON vault_items(user_id);

COMMENT ON INDEX idx_vault_items_user_id IS 'Ускоряет выборку элементов хранилища по владельцу';

-- Индекс для online-first синхронизации изменений по updated_at
CREATE INDEX idx_vault_items_user_updated_at
    ON vault_items(user_id, updated_at);

COMMENT ON INDEX idx_vault_items_user_updated_at IS 'Ускоряет синхронизацию изменений пользователя по времени обновления';

-- Индекс для поиска tombstones и будущей очистки soft-deleted записей
CREATE INDEX idx_vault_items_user_deleted_at
    ON vault_items(user_id, deleted_at)
    WHERE deleted_at IS NOT NULL;

COMMENT ON INDEX idx_vault_items_user_deleted_at IS 'Ускоряет выборку soft-deleted элементов пользователя';

-- Индекс для обычного списка активных элементов без удаленных записей
CREATE INDEX idx_vault_items_user_active_updated_at
    ON vault_items(user_id, updated_at)
    WHERE deleted_at IS NULL;

COMMENT ON INDEX idx_vault_items_user_active_updated_at IS 'Ускоряет постраничный список активных элементов пользователя';

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP INDEX IF EXISTS idx_vault_items_user_active_updated_at;
DROP INDEX IF EXISTS idx_vault_items_user_deleted_at;
DROP INDEX IF EXISTS idx_vault_items_user_updated_at;
DROP INDEX IF EXISTS idx_vault_items_user_id;

DROP TABLE IF EXISTS vault_items;
DROP TABLE IF EXISTS user_vaults;
DROP TABLE IF EXISTS users;

-- +goose StatementEnd
