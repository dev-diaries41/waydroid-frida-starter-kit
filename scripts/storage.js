Java.perform(function () {
    var SQLiteOpenHelper = Java.use("android.database.sqlite.SQLiteOpenHelper");
    var SQLiteDatabase = Java.use("android.database.sqlite.SQLiteDatabase");

    var processedDbPaths = new Set();
    var processedTables = {};

    var ignoreDbPaths = [
        "snowplowEvents", 
        "google_app_measurement_local.db", 
        "androidx.work.workdb",
        "com.google.android.datatransport.events"
    ];
    var ignoreTables = ["android_metadata", "sqlite_sequence"];
    var slowmode = false; // flag to stop excessive db reads of same dbs

    function shouldIgnoreDb(dbPath) {
        if (processedDbPaths.has(dbPath) && slowmode) {
            // console.log("Already processed");
            return true;
        }

        if (ignoreDbPaths.some(ignoreStr => dbPath.includes(ignoreStr))) {
            // console.log("Ignore list");
            return true;
        }

        return false;
    }

    function shouldIgnoreTable(tableName) {
        return ignoreTables.includes(tableName);
    }

    function getDb(callback) {
        try {
            SQLiteOpenHelper.getWritableDatabase.implementation = function () {
                var db = this.getWritableDatabase();
                var DB_PATH = db.getPath();

                if (DB_PATH && db.isOpen() && !shouldIgnoreDb(DB_PATH)) {
                    console.log("[INFO] Open Writable Database obtained: " + DB_PATH);
                    processedDbPaths.add(DB_PATH);
                    callback(DB_PATH, db); // Pass the db connection to callback
                }
                return db;
            };
        } catch (error) {
            console.log("[ERROR] Failed to get database: " + error.message);
        }
    }

    function getTables(dbPath, db) {
        var tables = [];
        try {
            var query = "SELECT name FROM sqlite_master WHERE type='table'";
            var cursor = db.rawQuery(query, null);

            while (cursor.moveToNext()) {
                var tableName = cursor.getString(cursor.getColumnIndex("name"));
                if (!shouldIgnoreTable(tableName)) {
                    tables.push(tableName);
                }
            }
            cursor.close();
        } catch (error) {
            if (error.message.includes("database is locked")) {
                console.log("[ERROR] Database is locked. Retrying...");
                retryOperation(getTables, dbPath, db);
            } else {
                console.log("[ERROR] Error checking available tables: " + error.message);
            }
        }
        return tables;
    }

    function retryOperation(func, dbPath, db, retries = 5, delay = 1000) {
        var attempts = 0;
        var success = false;

        function attempt() {
            try {
                console.log("[INFO] Attempt #" + (attempts + 1) + " to retry operation...");
                success = func(dbPath, db); // Try the function again
            } catch (error) {
                console.log("[ERROR] Retry failed: " + error.message);
            }
            if (!success && attempts < retries) {
                console.log("[INFO] Retrying after delay of " + delay + "ms...");
                setTimeout(attempt, delay);
                attempts++;
                delay *= 2; // Exponential backoff
            }
        }
        
        attempt(); // Initial attempt
        return success;
    }

    function readDataFromTable(db, table) {
        var tableData = [];
        try {
            var query = "SELECT * FROM " + table;
            var cursor = db.rawQuery(query, null);

            while (cursor.moveToNext()) {
                var row = {};
                var columnCount = cursor.getColumnCount();
                for (var i = 0; i < columnCount; i++) {
                    var columnName = cursor.getColumnName(i);
                    var columnType = cursor.getType(i);
                    var columnValue = processColumnValue(cursor, i, columnType);
                    row[columnName] = columnValue;
                }
                tableData.push(row);
            }
            cursor.close();
        } catch (e) {
            console.log("[ERROR] Error reading table " + table + ": " + e.message);
        }

        return tableData;
    }

    function processColumnValue(cursor, columnIndex, columnType) {
        var columnValue = null;
        try {
            if (columnType === 0) {
                columnValue = "[NULL]";
            } else if (columnType === 1) {
                columnValue = cursor.getInt(columnIndex);
            } else if (columnType === 2) {
                columnValue = cursor.getDouble(columnIndex);
            } else if (columnType === 3) {
                columnValue = cursor.getString(columnIndex);
            } else if (columnType === 4) {
                var blob = cursor.getBlob(columnIndex);
                columnValue = "data:application/octet-stream;base64," + Java.array('byte', blob).toString();
            }
        } catch (e) {
            console.log("[ERROR] Error reading column at index " + columnIndex + ": " + e.message);
            columnValue = "[Error reading value]";  // Handle error gracefully
        }

        return columnValue;
    }

    function readAllDataFromTables(dbPath, db, tables) {
        var allDataRecord = {};
        try {
            tables.forEach(function (table, index) {
                var shouldSkip = processedTables[dbPath] && processedTables[dbPath].has(table);
                if (shouldSkip) {
                    return;
                }

                if (index > 0) {
                    sleep(1000);
                }

                console.log("[INFO] Reading table: " + table);
                var tableData = readDataFromTable(db, table);
                if (tableData.length > 0) {
                    allDataRecord[table] = tableData;
                    if (!processedTables[dbPath]) {
                        processedTables[dbPath] = new Set();
                    }
                    processedTables[dbPath].add(table);
                }
            });
        } catch (error) {
            console.log("[ERROR] Error during data read from tables: " + error.message);
            return null;
        }
        return allDataRecord;
    }

    // Asynchronous sleep
    function sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    getDb(async function (DB_PATH, db) {
        if (DB_PATH) {
            var availableTables = getTables(DB_PATH, db);
            if (availableTables && availableTables.length > 0) {
                console.log("[INFO] Available Tables:", availableTables);
            }

            var allData = await readAllDataFromTables(DB_PATH, db, availableTables);
            if (allData) {
                send(allData);
                console.log("[INFO] All Data:", JSON.stringify(allData, null, 2));
            }

            // Example: Uncomment to add data to a specific table (e.g., WorkSpec)
            // addData(DB_PATH, "android_metadata", "locale", "en_US");
        }
    });
});
