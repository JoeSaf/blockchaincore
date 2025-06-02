#pragma once

#include <string>
#include <vector>
#include <memory>
#include <unordered_map>
#include <mutex>
#include <fstream>
#include <nlohmann/json.hpp>
#include "Blockchain.h"
#include "../blockchain/Block.h"
#include "../blockchain/Transaction.h"

// File metadata structure
struct FileMetadata {
    std::string fileId;           // Unique file identifier
    std::string originalName;     // Original filename
    std::string mimeType;         // File MIME type
    uint64_t fileSize;           // Total file size in bytes
    std::string fileHash;        // SHA-256 hash of complete file
    uint32_t totalChunks;        // Number of chunks
    uint64_t chunkSize;          // Size of each chunk (except last)
    std::time_t uploadTime;      // When file was uploaded
    std::string uploaderAddress; // Address of uploader
    bool isComplete;             // All chunks received
    std::vector<std::string> chunkHashes; // Hash of each chunk
    nlohmann::json permissions;  // File access permissions
    
    nlohmann::json toJson() const;
    void fromJson(const nlohmann::json& json);
};

// File chunk data
struct FileChunk {
    std::string fileId;
    uint32_t chunkIndex;
    std::vector<uint8_t> data;
    std::string chunkHash;
    bool isLastChunk;
    
    nlohmann::json toJson() const;
    void fromJson(const nlohmann::json& json);
    std::string calculateHash() const;
};

// File transaction - specialized transaction for file operations
class FileTransaction : public Transaction {
public:
    enum class FileOperation {
        UPLOAD_METADATA,    // Initial file metadata
        UPLOAD_CHUNK,       // File chunk data
        DELETE_FILE,        // File deletion
        UPDATE_PERMISSIONS, // Permission changes
        FILE_ACCESS_LOG     // Access logging
    };
    
    // Constructor for file operations
    FileTransaction(FileOperation operation, const std::string& userAddress);
    
    // File-specific operations
    void setFileMetadata(const FileMetadata& metadata);
    void setFileChunk(const FileChunk& chunk);
    void setFileId(const std::string& fileId);
    void setPermissions(const nlohmann::json& permissions);
    
    // Getters
    FileOperation getFileOperation() const { return fileOperation_; }
    const FileMetadata& getFileMetadata() const { return fileMetadata_; }
    const FileChunk& getFileChunk() const { return fileChunk_; }
    const std::string& getFileId() const { return fileId_; }
    
    // Validation
    bool isValidFileTransaction() const override;
    
    // JSON serialization
    nlohmann::json toJson() const override;
    void fromJson(const nlohmann::json& json) override;

private:
    FileOperation fileOperation_;
    FileMetadata fileMetadata_;
    FileChunk fileChunk_;
    std::string fileId_;
    nlohmann::json permissions_;
};

// File block - specialized block for file storage
class FileBlock : public Block {
public:
    // Constructor
    FileBlock(uint32_t index, const std::string& previousHash, 
              const std::vector<FileTransaction>& fileTransactions);
    
    // File-specific operations
    std::vector<FileTransaction> getFileTransactions() const;
    bool addFileTransaction(const FileTransaction& transaction);
    
    // File integrity validation
    bool validateFileIntegrity() const;
    std::vector<std::string> getStoredFileIds() const;
    uint64_t getTotalStoredBytes() const;
    
    // JSON serialization
    nlohmann::json toJson() const override;
    void fromJson(const nlohmann::json& json) override;

private:
    std::vector<FileTransaction> fileTransactions_;
    uint64_t totalStoredBytes_;
    uint32_t fileCount_;
};

// Main file blockchain system
class FileBlockchain : public Blockchain {
public:
    // Constructor
    FileBlockchain();
    
    // Destructor
    ~FileBlockchain() = default;
    
    // ========================
    // FILE UPLOAD OPERATIONS
    // ========================
    
    // Upload a complete file
    std::string uploadFile(const std::string& filePath, const std::string& uploaderAddress);
    std::string uploadFileData(const std::vector<uint8_t>& fileData, const std::string& filename,
                              const std::string& uploaderAddress);
    
    // Chunked upload operations
    std::string initiateFileUpload(const std::string& filename, uint64_t fileSize,
                                  const std::string& uploaderAddress);
    bool uploadFileChunk(const std::string& fileId, uint32_t chunkIndex, 
                        const std::vector<uint8_t>& chunkData);
    bool finalizeFileUpload(const std::string& fileId);
    
    // ========================
    // FILE DOWNLOAD OPERATIONS
    // ========================
    
    // Download complete file
    std::vector<uint8_t> downloadFile(const std::string& fileId);
    bool downloadFileToPath(const std::string& fileId, const std::string& outputPath);
    
    // Chunked download operations
    std::vector<uint8_t> downloadFileChunk(const std::string& fileId, uint32_t chunkIndex);
    std::vector<FileChunk> getAllFileChunks(const std::string& fileId);
    
    // ========================
    // FILE MANAGEMENT
    // ========================
    
    // File queries
    std::vector<FileMetadata> listFiles(const std::string& userAddress = "");
    FileMetadata getFileMetadata(const std::string& fileId);
    bool fileExists(const std::string& fileId);
    std::vector<std::string> findFilesByName(const std::string& filename);
    
    // File operations
    bool deleteFile(const std::string& fileId, const std::string& userAddress);
    bool updateFilePermissions(const std::string& fileId, const nlohmann::json& permissions,
                              const std::string& userAddress);
    bool renameFile(const std::string& fileId, const std::string& newName, 
                   const std::string& userAddress);
    
    // File integrity and verification
    bool verifyFileIntegrity(const std::string& fileId);
    std::string calculateFileHash(const std::string& fileId);
    bool repairCorruptedFile(const std::string& fileId);
    
    // ========================
    // FILE SEARCH AND INDEXING
    // ========================
    
    // Search operations
    std::vector<FileMetadata> searchFiles(const std::string& query);
    std::vector<FileMetadata> getFilesByType(const std::string& mimeType);
    std::vector<FileMetadata> getFilesByUser(const std::string& userAddress);
    std::vector<FileMetadata> getFilesByDateRange(std::time_t startTime, std::time_t endTime);
    
    // File statistics
    uint64_t getTotalStorageUsed() const;
    uint64_t getUserStorageUsed(const std::string& userAddress) const;
    uint32_t getTotalFileCount() const;
    std::vector<std::string> getMostActiveUsers() const;
    
    // ========================
    // PERMISSION MANAGEMENT
    // ========================
    
    // Permission operations
    bool hasFileAccess(const std::string& fileId, const std::string& userAddress, 
                      const std::string& operation = "read");
    bool grantFileAccess(const std::string& fileId, const std::string& userAddress,
                        const std::string& permissions);
    bool revokeFileAccess(const std::string& fileId, const std::string& userAddress);
    nlohmann::json getFilePermissions(const std::string& fileId);
    
    // ========================
    // STORAGE OPTIMIZATION
    // ========================
    
    // Deduplication
    bool enableDeduplication(bool enable) { deduplicationEnabled_ = enable; return true; }
    std::vector<std::string> findDuplicateFiles();
    bool mergeDuplicateFiles(const std::vector<std::string>& fileIds);
    
    // Compression
    bool enableCompression(bool enable) { compressionEnabled_ = enable; return true; }
    std::vector<uint8_t> compressData(const std::vector<uint8_t>& data);
    std::vector<uint8_t> decompressData(const std::vector<uint8_t>& compressedData);
    
    // Garbage collection
    void performGarbageCollection();
    std::vector<std::string> findOrphanedChunks();
    void cleanupOrphanedChunks();
    
    // ========================
    // BLOCKCHAIN OVERRIDES
    // ========================
    
    // Enhanced block operations for files
    FileBlock createFileBlock(const std::vector<FileTransaction>& transactions);
    bool addFileBlock(const FileBlock& block);
    bool isValidFileBlock(const FileBlock& block, const FileBlock* previousBlock) const;
    
    // File-specific validation
    bool validateFileChainIntegrity() const;
    bool validateAllFileIntegrity() const;
    
    // ========================
    // PERSISTENCE AND BACKUP
    // ========================
    
    // Save/load operations
    bool saveFileIndex(const std::string& filename) const;
    bool loadFileIndex(const std::string& filename);
    bool exportFileMetadata(const std::string& filename) const;
    bool importFileMetadata(const std::string& filename);
    
    // Backup operations
    bool createBackup(const std::string& backupPath);
    bool restoreFromBackup(const std::string& backupPath);
    
    // ========================
    // CONFIGURATION
    // ========================
    
    struct FileBlockchainConfig {
        uint64_t maxChunkSize = 1024 * 1024;        // 1MB chunks
        uint64_t maxFileSize = 100 * 1024 * 1024;   // 100MB max file
        uint64_t maxStoragePerUser = 1024 * 1024 * 1024; // 1GB per user
        bool enableCompression = true;
        bool enableDeduplication = true;
        bool enableEncryption = false;
        uint32_t maxFilesPerBlock = 50;
        
        nlohmann::json toJson() const;
        void fromJson(const nlohmann::json& json);
    };
    
    void setConfig(const FileBlockchainConfig& config) { config_ = config; }
    const FileBlockchainConfig& getConfig() const { return config_; }

private:
    // File storage state
    std::unordered_map<std::string, FileMetadata> fileIndex_;      // fileId -> metadata
    std::unordered_map<std::string, std::vector<FileChunk>> fileChunks_; // fileId -> chunks
    std::unordered_map<std::string, std::string> hashToFileId_;    // file hash -> fileId
    std::unordered_map<std::string, std::vector<std::string>> userFiles_; // user -> fileIds
    
    // Configuration
    FileBlockchainConfig config_;
    bool deduplicationEnabled_;
    bool compressionEnabled_;
    bool encryptionEnabled_;
    
    // Thread safety
    mutable std::mutex fileIndexMutex_;
    mutable std::mutex chunksMutex_;
    
    // Internal operations
    std::string generateFileId(const std::string& filename, const std::string& userAddress);
    std::vector<FileChunk> splitFileIntoChunks(const std::vector<uint8_t>& fileData, 
                                             const std::string& fileId);
    std::vector<uint8_t> reconstructFileFromChunks(const std::vector<FileChunk>& chunks);
    
    // Validation helpers
    bool isValidFileId(const std::string& fileId) const;
    bool isValidChunkIndex(const std::string& fileId, uint32_t chunkIndex) const;
    bool hasAllChunks(const std::string& fileId) const;
    
    // Storage management
    void updateFileIndex(const FileMetadata& metadata);
    void addFileChunk(const std::string& fileId, const FileChunk& chunk);
    void removeFileFromIndex(const std::string& fileId);
    void updateUserFileList(const std::string& userAddress, const std::string& fileId, bool add = true);
    
    // Security and permissions
    bool validateUserAccess(const std::string& fileId, const std::string& userAddress, 
                           const std::string& operation) const;
    nlohmann::json createDefaultPermissions(const std::string& ownerAddress);
    bool isOwner(const std::string& fileId, const std::string& userAddress) const;
    
    // Utility functions
    std::string detectMimeType(const std::string& filename, const std::vector<uint8_t>& data);
    std::string formatFileSize(uint64_t bytes) const;
    std::vector<uint8_t> readFileFromDisk(const std::string& filePath);
    bool writeFileToDisk(const std::string& filePath, const std::vector<uint8_t>& data);
    
    // Deduplication helpers
    bool isDuplicateFile(const std::string& fileHash) const;
    std::string findExistingFileByHash(const std::string& fileHash) const;
    void linkDuplicateFile(const std::string& newFileId, const std::string& existingFileId);
    
    // Compression helpers (placeholder for future implementation)
    bool shouldCompressFile(const FileMetadata& metadata) const;
    std::vector<uint8_t> compressChunk(const std::vector<uint8_t>& chunkData);
    std::vector<uint8_t> decompressChunk(const std::vector<uint8_t>& compressedData);
    
    // Blockchain integration helpers
    void processFileTransaction(const FileTransaction& transaction);
    void updateBlockchainState(const FileBlock& block);
    bool validateFileTransactionSequence(const std::vector<FileTransaction>& transactions) const;
};