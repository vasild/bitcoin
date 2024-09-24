// Copyright (c) 2024-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_COMMON_SOCKMAN_H
#define BITCOIN_COMMON_SOCKMAN_H

#include <i2p.h>
#include <netaddress.h>
#include <netbase.h>
#include <util/fs.h>
#include <util/sock.h>
#include <util/translation.h>

#include <atomic>
#include <memory>
#include <queue>
#include <thread>
#include <variant>
#include <vector>

typedef int64_t NodeId;

CService GetBindAddress(const Sock& sock);

/**
 * A socket manager class which handles socket operations.
 * To use this class, inherit from it and implement the pure virtual methods.
 * Handled operations:
 * - binding and listening on sockets
 * - starting of necessary threads to process socket operations
 * - accepting incoming connections
 * - making outbound connections
 */
class SockMan
{
public:

    virtual ~SockMan() = default;

    //
    // Non-virtual functions, to be reused by children classes.
    //

    /**
     * Bind to a new address:port, start listening and add the listen socket to `m_listen`.
     * Should be called before `StartSocketsThreads()`.
     * @param[in] to Where to bind.
     * @param[out] errmsg Error string if an error occurs.
     * @retval true Success.
     * @retval false Failure, `strError` will be set.
     */
    bool BindAndStartListening(const CService& to, bilingual_str& errmsg);

    /**
     * Options to influence `StartSocketsThreads()`.
     */
    struct Options {
        struct I2P {
            explicit I2P(const fs::path& file, const Proxy& proxy) : private_key_file{file}, sam_proxy{proxy} {}

            const fs::path private_key_file;
            const Proxy sam_proxy;
        };

        /**
         * I2P options. If set then a thread will be started that will accept incoming I2P connections.
         */
        std::optional<I2P> i2p;
    };

    /**
     * Start the necessary threads for sockets IO.
     */
    void StartSocketsThreads(const Options& options);

    /**
     * Join (wait for) the threads started by `StartSocketsThreads()` to exit.
     */
    void JoinSocketsThreads();

    /**
     * A more readable std::tuple<std::string, uint16_t> for host and port.
     */
    struct StringHostIntPort {
        const std::string& host;
        uint16_t port;
    };

    /**
     * Make an outbound connection, save the socket internally and return a newly generated node id.
     * @param[in] to The address to connect to, either as CService or a host as string and port as
     * an integer, if the later is used, then `proxy` must be valid.
     * @param[in] is_important If true, then log failures with higher severity.
     * @param[in] proxy Proxy to connect through if `proxy.IsValid()` is true.
     * @param[out] proxy_failed If `proxy` is valid and the connection failed because of the
     * proxy, then it will be set to true.
     * @param[out] me If the connection was successful then this is set to the address on the
     * local side of the socket.
     * @param[out] sock Connected socket, if the operation is successful.
     * @param[out] i2p_transient_session I2P session, if the operation is successful.
     * @return Newly generated node id, or std::nullopt if the operation fails.
     */
    std::optional<NodeId> ConnectAndMakeNodeId(const std::variant<CService, StringHostIntPort>& to,
                                               bool is_important,
                                               const Proxy& proxy,
                                               bool& proxy_failed,
                                               CService& me,
                                               std::unique_ptr<Sock>& sock,
                                               std::unique_ptr<i2p::sam::Session>& i2p_transient_session)
        EXCLUSIVE_LOCKS_REQUIRED(!m_unused_i2p_sessions_mutex);

    /**
     * Accept a connection.
     * @param[in] listen_sock Socket on which to accept the connection.
     * @param[out] addr Address of the peer that was accepted.
     * @return Newly created socket for the accepted connection.
     */
    std::unique_ptr<Sock> AcceptConnection(const Sock& listen_sock, CService& addr);

    /**
     * After a new socket with a peer has been created, configure its flags,
     * make a new node id and call `EventNewConnectionAccepted()`.
     * @param[in] sock The newly created socket.
     * @param[in] me Address at our end of the connection.
     * @param[in] them Address of the new peer.
     */
    void NewSockAccepted(std::unique_ptr<Sock>&& sock, const CService& me, const CService& them);

    /**
     * Generate an id for a newly created node.
     */
    NodeId GetNewNodeId();

    /**
     * Close all sockets.
     */
    void CloseSockets();

    /**
     * This is signaled when network activity should cease.
     * A pointer to it is saved in `m_i2p_sam_session`, so make sure that
     * the lifetime of `interruptNet` is not shorter than
     * the lifetime of `m_i2p_sam_session`.
     */
    CThreadInterrupt interruptNet;

    /**
     * I2P SAM session.
     * Used to accept incoming and make outgoing I2P connections from a persistent
     * address.
     */
    std::unique_ptr<i2p::sam::Session> m_i2p_sam_session;

    /**
     * List of listening sockets.
     */
    std::vector<std::shared_ptr<Sock>> m_listen;

private:

    /**
     * Cap on the size of `m_unused_i2p_sessions`, to ensure it does not
     * unexpectedly use too much memory.
     */
    static constexpr size_t MAX_UNUSED_I2P_SESSIONS_SIZE{10};

    //
    // Pure virtual functions must be implemented by children classes.
    //

    /**
     * Be notified when a new connection has been accepted.
     * @param[in] node_id Id of the newly accepted connection.
     * @param[in] sock Connected socket to communicate with the peer.
     * @param[in] me The address and port at our side of the connection.
     * @param[in] them The address and port at the peer's side of the connection.
     */
    virtual void EventNewConnectionAccepted(NodeId node_id,
                                            std::unique_ptr<Sock>&& sock,
                                            const CService& me,
                                            const CService& them) = 0;

    /**
     * Called when the socket is ready to send data and `ShouldTryToSend()` has
     * returned true. This is where the higher level code serializes its messages
     * and calls `SockMan::SendBytes()`.
     * @param[in] node_id Id of the node whose socket is ready to send.
     * @param[out] cancel_recv Should always be set upon return and if it is true,
     * then the next attempt to receive data from that node will be omitted.
     */
    virtual void EventReadyToSend(NodeId node_id, bool& cancel_recv) = 0;

    /**
     * Called when new data has been received.
     * @param[in] node_id Node for which the data arrived.
     * @param[in] data Data buffer.
     * @param[in] n Number of bytes in `data`.
     */
    virtual void EventGotData(NodeId node_id, const uint8_t* data, size_t n) = 0;

    /**
     * Called when the remote peer has sent an EOF on the socket. This is a graceful
     * close of their writing side, we can still send and they will receive, if it
     * makes sense at the application level.
     * @param[in] node_id Node whose socket got EOF.
     */
    virtual void EventGotEOF(NodeId node_id) = 0;

    /**
     * Called when we get an irrecoverable error trying to read from a socket.
     * @param[in] node_id Node whose socket got an error.
     * @param[in] errmsg Message describing the error.
     */
    virtual void EventGotPermanentReadError(NodeId node_id, const std::string& errmsg) = 0;

    //
    // Non-pure virtual functions can be overridden by children classes or left
    // alone to use the default implementation from SockMan.
    //

    /**
     * SockMan would only call EventReadyToSend() if this returns true.
     * Can be used to temporarily pause sends for a node.
     * The implementation in SockMan always returns true.
     * @param[in] node_id Node for which to confirm or cancel a call to EventReadyToSend().
     */
    virtual bool ShouldTryToSend(NodeId node_id) const;

    /**
     * SockMan would only call Recv() on a node's socket if this returns true.
     * Can be used to temporarily pause receives for a node.
     * The implementation in SockMan always returns true.
     * @param[in] node_id Node for which to confirm or cancel a receive.
     */
    virtual bool ShouldTryToRecv(NodeId node_id) const;

    /**
     * SockMan has completed the current send+recv iteration for a node.
     * It will do another send+recv for this node after processing all other nodes.
     * Can be used to execute periodic tasks for a given node.
     * The implementation in SockMan does nothing.
     * @param[in] node_id Node for which send+recv has been done.
     */
    virtual void EventIOLoopCompletedForNode(NodeId node_id);

    /**
     * SockMan has completed send+recv for all nodes.
     * Can be used to execute periodic tasks for all nodes, like disconnecting
     * nodes due to higher level logic.
     * The implementation in SockMan does nothing.
     */
    virtual void EventIOLoopCompletedForAllPeers();

    /**
     * Be notified of a change in the state of listening for incoming I2P connections.
     * The default behavior, implemented by `SockMan`, is to ignore this event.
     * @param[in] addr Our listening address.
     * @param[in] success If true then the listen succeeded and we are now
     * listening for incoming I2P connections at `addr`. If false then the
     * call failed and now we are not listening (even if this was invoked
     * before with `true`).
     */
    virtual void EventI2PListen(const CService& addr, bool success);

    /**
     * Accept incoming I2P connections in a loop and call
     * `EventNewConnectionAccepted()` for each new connection.
     */
    void ThreadI2PAccept();

    /**
     * The id to assign to the next created node. Used to generate ids of nodes.
     */
    std::atomic<NodeId> m_next_node_id{0};

    /**
     * Thread that accepts incoming I2P connections in a loop, can be stopped via `interruptNet`.
     */
    std::thread m_thread_i2p_accept;

    /**
     * Mutex protecting m_i2p_sam_sessions.
     */
    Mutex m_unused_i2p_sessions_mutex;

    /**
     * A pool of created I2P SAM transient sessions that should be used instead
     * of creating new ones in order to reduce the load on the I2P network.
     * Creating a session in I2P is not cheap, thus if this is not empty, then
     * pick an entry from it instead of creating a new session. If connecting to
     * a host fails, then the created session is put to this pool for reuse.
     */
    std::queue<std::unique_ptr<i2p::sam::Session>> m_unused_i2p_sessions GUARDED_BY(m_unused_i2p_sessions_mutex);
};

#endif // BITCOIN_COMMON_SOCKMAN_H