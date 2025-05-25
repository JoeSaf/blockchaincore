// python_bindings.cpp - FIXED VERSION
#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <pybind11/chrono.h>
#include <pybind11/functional.h>
#include <pybind11/iostream.h>
#include "blockchain_core.hpp"

namespace py = pybind11;
using namespace blockchain;

PYBIND11_MODULE(blockchain_core, m) {
    m.doc() = "High-performance C++ blockchain core with Python bindings";
    
    // CryptoUtils class
    py::class_<CryptoUtils>(m, "CryptoUtils")
        .def_static("sha256", &CryptoUtils::sha256, "Calculate SHA256 hash of a string")
        .def_static("base64_encode", &CryptoUtils::base64_encode, "Encode bytes to base64")
        .def_static("base64_decode", &CryptoUtils::base64_decode, "Decode base64 to bytes")
        .def_static("generate_rsa_keypair", &CryptoUtils::generate_rsa_keypair, "Generate RSA key pair")
        .def_static("encrypt_private_key", &CryptoUtils::encrypt_private_key, "Encrypt private key with password")
        .def_static("decrypt_private_key", &CryptoUtils::decrypt_private_key, "Decrypt private key with password")
        .def_static("sign_message", &CryptoUtils::sign_message, "Sign message with private key")
        .def_static("verify_signature", &CryptoUtils::verify_signature, "Verify signature with public key");
    
    // Block class
    py::class_<Block>(m, "Block")
        .def(py::init<size_t, double, const nlohmann::json&, const std::string&>(),
             "Create a new block", 
             py::arg("index"), py::arg("timestamp"), py::arg("data"), py::arg("previous_hash"))
        .def("calculate_hash", &Block::calculate_hash, "Calculate block hash")
        .def("to_json", &Block::to_json, "Convert block to JSON")
        .def_static("from_json", &Block::from_json, "Create block from JSON")
        .def("get_index", &Block::get_index, "Get block index")
        .def("get_timestamp", &Block::get_timestamp, "Get block timestamp")
        .def("get_data", &Block::get_data, "Get block data")
        .def("get_hash", &Block::get_hash, "Get block hash")
        .def("get_previous_hash", &Block::get_previous_hash, "Get previous block hash")
        .def("set_index", &Block::set_index, "Set block index")
        .def("set_previous_hash", &Block::set_previous_hash, "Set previous block hash")
        .def("recalculate_hash", &Block::recalculate_hash, "Recalculate block hash");
    
    // User class
    py::class_<User>(m, "User")
        .def(py::init<const std::string&, const std::string&, const std::string&>(),
             "Create a new user with password",
             py::arg("username"), py::arg("role"), py::arg("password") = "")
        .def(py::init<const std::string&, const std::string&, const std::string&, const std::string&>(),
             "Create user with existing keys",
             py::arg("username"), py::arg("role"), py::arg("public_key"), py::arg("private_key"))
        .def("get_public_key_pem", &User::get_public_key_pem, "Get public key in PEM format")
        .def("get_private_key_pem", &User::get_private_key_pem, "Get private key in PEM format", py::arg("password") = "")
        .def("sign_message", &User::sign_message, "Sign a message")
        .def("verify_password", &User::verify_password, "Verify user password")
        .def("initialize_user_folder", &User::initialize_user_folder, "Initialize user folder")
        .def("store_user_item", &User::store_user_item, "Store item in user folder")
        .def("get_username", &User::get_username, "Get username")
        .def("get_role", &User::get_role, "Get user role");
    
    // Blockchain class - FIXED: Remove unique_ptr binding issue
    py::class_<Blockchain>(m, "Blockchain")
        .def(py::init<const std::string&>(), 
             "Create blockchain with database file", 
             py::arg("db_file") = "blockchain_db.json")
        // FIXED: Remove the problematic add_block method with unique_ptr
        // .def("add_block", [](Blockchain& self, std::unique_ptr<Block> block) {
        //     self.add_block(std::move(block));
        // }, "Add block to blockchain")
        .def("is_chain_valid", &Blockchain::is_chain_valid, "Validate blockchain integrity")
        .def("save_chain", &Blockchain::save_chain, "Save blockchain to file")
        .def("load_chain", &Blockchain::load_chain, "Load blockchain from file")
        .def("rehash_chain", &Blockchain::rehash_chain, "Rehash entire blockchain")
        .def("get_latest_block", &Blockchain::get_latest_block, 
             "Get latest block", py::return_value_policy::reference_internal)
        .def("get_chain_length", &Blockchain::get_chain_length, "Get blockchain length")
        .def("to_json", &Blockchain::to_json, "Convert blockchain to JSON")
        .def("safely_reorder_blocks", &Blockchain::safely_reorder_blocks, "Reorder blocks safely")
        .def("create_genesis_block", &Blockchain::create_genesis_block, "Create genesis block")
        .def("trigger_fallback_response", &Blockchain::trigger_fallback_response, "Trigger security fallback")
        .def("start_block_adjuster", &Blockchain::start_block_adjuster, 
             "Start block adjuster", py::arg("interval_seconds") = 300)
        .def("stop_block_adjuster", &Blockchain::stop_block_adjuster, "Stop block adjuster");
    
    // AuthSystem class
    py::class_<AuthSystem>(m, "AuthSystem")
        .def(py::init<>(), "Create authentication system")
        .def("register_user", &AuthSystem::register_user, 
             "Register new user", py::arg("username"), py::arg("role"), py::arg("password"))
        .def("authenticate", &AuthSystem::authenticate, 
             "Authenticate user", py::arg("username"), py::arg("password"))
        .def("list_users", &AuthSystem::list_users, "List all users")
        .def("verify_blockchain", &AuthSystem::verify_blockchain, "Verify blockchain integrity")
        .def("load_users_from_blockchain", &AuthSystem::load_users_from_blockchain, "Load users from blockchain")
        .def("get_blockchain", py::overload_cast<>(&AuthSystem::get_blockchain), 
             "Get blockchain instance", py::return_value_policy::reference_internal)
        .def("user_exists", &AuthSystem::user_exists, "Check if user exists")
        .def("get_user_role", &AuthSystem::get_user_role, "Get user role");
    
    // BlockchainCore class (main interface)
    py::class_<BlockchainCore>(m, "BlockchainCore")
        .def_static("get_instance", &BlockchainCore::get_instance, 
                    "Get singleton instance", py::return_value_policy::reference)
        .def("initialize", &BlockchainCore::initialize, "Initialize blockchain system")
        .def("register_user", &BlockchainCore::register_user, 
             "Register new user", py::arg("username"), py::arg("role"), py::arg("password"))
        .def("authenticate", &BlockchainCore::authenticate, 
             "Authenticate user", py::arg("username"), py::arg("password"))
        .def("list_users", &BlockchainCore::list_users, "List all users")
        .def("verify_blockchain", &BlockchainCore::verify_blockchain, "Verify blockchain integrity")
        .def("get_blockchain_data", &BlockchainCore::get_blockchain_data, "Get blockchain data as JSON")
        .def("add_custom_block", &BlockchainCore::add_custom_block, "Add custom block to blockchain")
        .def("get_chain_length", &BlockchainCore::get_chain_length, "Get blockchain length")
        .def("start_block_adjuster", &BlockchainCore::start_block_adjuster, 
             "Start block adjuster", py::arg("interval_seconds") = 300)
        .def("stop_block_adjuster", &BlockchainCore::stop_block_adjuster, "Stop block adjuster")
        .def("save_state", &BlockchainCore::save_state, "Save blockchain state")
        .def("load_state", &BlockchainCore::load_state, "Load blockchain state")
        .def("setup_directories", &BlockchainCore::setup_directories, "Setup required directories")
        .def("get_auth_system", &BlockchainCore::get_auth_system, 
             "Get auth system", py::return_value_policy::reference_internal);
    
    // Utility functions
    m.def("current_timestamp", []() {
        return std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
    }, "Get current timestamp");
    
    m.def("format_time", [](double timestamp) {
        auto time_t_val = static_cast<time_t>(timestamp);
        auto tm_val = *std::localtime(&time_t_val);
        char buffer[100];
        std::strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", &tm_val);
        return std::string(buffer);
    }, "Format timestamp to readable string");
    
    // Version info
    m.attr("__version__") = "1.0.0";
    m.attr("__author__") = "Blockchain Core Team";
}