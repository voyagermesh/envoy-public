#include "contrib/mysql_proxy/filters/network/source/mysql_filter.h"

#include "envoy/config/core/v3/base.pb.h"

#include "source/common/buffer/buffer_impl.h"
#include "source/common/common/assert.h"
#include "source/common/common/logger.h"
#include "source/extensions/filters/network/well_known_names.h"

#include "contrib/mysql_proxy/filters/network/source/mysql_codec.h"
#include "contrib/mysql_proxy/filters/network/source/mysql_codec_clogin_resp.h"
#include "contrib/mysql_proxy/filters/network/source/mysql_decoder_impl.h"

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace MySQLProxy {

MySQLFilterConfig::MySQLFilterConfig(const MySQLFilterConfigOptions& config_options, Stats::Scope& scope)
    : scope_(scope), stats_(generateStats(config_options.stat_prefix, scope)), terminate_downstream_tls_(config_options.terminate_downstream_tls), upstream_tls_(config_options.upstream_tls) {}

MySQLFilter::MySQLFilter(MySQLFilterConfigSharedPtr config) : config_(std::move(config)) {}

void MySQLFilter::initializeReadFilterCallbacks(Network::ReadFilterCallbacks& callbacks) {
  read_callbacks_ = &callbacks;
}

Network::FilterStatus MySQLFilter::onData(Buffer::Instance& data, bool endBuf) {
  // Safety measure just to make sure that if we have a decoding error we keep going and lose stats.
  // This can be removed once we are more confident of this code.
  std::cout<< "ONdata RAW\n\n\n";
  printData(data,20);
  if(initialHandshakeStage){
    if(shouldTerminateDownstreamTLS()){

      if(shouldEncryptUpstream()){
        if(!down_tls_on){
          Buffer::OwnedImpl temp;
          temp.add(data);

          if(read_callbacks_->connection().startSecureTransport()){
            printf("Downstream SSL established\n");
          }
          else{
            printf("Downstream SSL Failed\n");
          }
          down_tls_on = true;

          read_callbacks_->connection().addBytesSentCallback([](uint64_t bytes) ->bool {
            if(bytes>0)
              std::cout<<"Came Here"<<std::endl;
            return true;
          });
          // data.drain(data.length());
          // data.add(getClientHelloPacket());

        }
        else if(!up_tls_on){


          if(read_callbacks_->startUpstreamSecureTransport()){
            printf("Started upstream TLS\n");
          }
          else{
            printf("Failed upstream TLS\n");
          }

          up_tls_on = true;
        }
        else{
          initialHandshakeStage = false;
        }
      }
      else{
        if(!down_tls_on){

          if(read_callbacks_->connection().startSecureTransport()){
            printf("Downstream SSL established\n");
          }
          else{
            printf("Downstream SSL Failed\n");
          }

          down_tls_on = true;
          read_buffer_.add(data);
          doDecode(read_buffer_);
          data.drain(data.length());
          /*Buffer::OwnedImpl tls_request_buffer = getClientHelloPacket();
          read_buffer_.add(tls_request_buffer);
          doDecode(read_buffer_);*/
          return Network::FilterStatus::StopIteration;
        }
        else if(!handshake_done){
          Buffer::OwnedImpl tmpData;
          if(!up_tls_on){
            tmpData = getDataWithNewIndex(data, 1, true);
            up_tls_on = true;
          }
          else{
            tmpData = changeBufferIdx(data,1,true);
          }


          //printData(tmpData, 10);
          data.drain(data.length());
          data.add(tmpData);

          read_buffer_.add(data);
          doDecode(read_buffer_);

          if(endBuf){
            initialHandshakeStage = false;
          }

          return Network::FilterStatus::Continue;
        }
      }
    }
    else {
      if(shouldEncryptUpstream()){

        if(true){

          Buffer::OwnedImpl tmp_buffer;
          //tmp_buffer = getDataWithNewIndex(data,1,false);

          if(!up_tls_on){
            tmp_buffer = getDataWithNewIndex(data,1,false);
            if(read_callbacks_->startUpstreamSecureTransport()){
              std::cout<< " UPSTREAM TLS ON\n";
            }
            else{
              std::cout<<"FAILED TO ACTIVATE UPSTREAM TLS\n";
            }
          }
          else{
            tmp_buffer = changeBufferIdx(data,1,false);
          }

          data.drain(data.length());
          data.add(tmp_buffer);
          up_tls_on = true;

        }
        else{
          initialHandshakeStage = false;
        }
      }
      else{

      }
    }
  }


  if (sniffing_) {
    read_buffer_.add(data);
    doDecode(read_buffer_);
  }

  //return Network::FilterStatus::StopIteration;
  return Network::FilterStatus::Continue;
}

Network::FilterStatus MySQLFilter::onWrite(Buffer::Instance& data, bool) {

  std::cout<< " Printing Write Data\n\n";
  printData(data,20);
  if(shouldIncreaseWriteBufIdx){
    auto newData = changeBufferIdxForWrite(data, 1, false);
    data.drain(data.length());
    data.add(newData);
    shouldIncreaseWriteBufIdx = false;
    initialHandshakeStage = false;
  }
  else if(initialHandshakeStage && !shouldEncryptUpstream() && shouldTerminateDownstreamTLS()){
    auto newData = onSSLFlagInClientHello(data);
    data.drain(data.length());
    data.add(newData);

    shouldIncreaseWriteBufIdx = true;
  }

  if(shouldEncryptUpstream() && !shouldTerminateDownstreamTLS()){
    if(!sslReqSentUp){
      temp_storage_ = getClientHelloPacket();
      std::cout<<"SSL request data printing\n";
      printData(temp_storage_,40);

      read_callbacks_->connection().addBytesSentCallback(
          [=](uint64_t bytes) -> bool {
            std::cout<<bytes<<std::endl;
            read_callbacks_->injectReadDataToFilterChain(temp_storage_,false);

            return false;
          }
      );
      sslReqSentUp = true;
    }
    else if(initialHandshakeStage){

      auto tmp_data = changeBufferIdxForWrite(data,1,true);
      data.drain(data.length());
      data.add(tmp_data);

      initialHandshakeStage = false;

    }

  }

  printData(data,10);
  // Safety measure just to make sure that if we have a decoding error we keep going and lose stats.
  // This can be removed once we are more confident of this code.

    /*if(waiting_for_upTls && read_callbacks_->startUpstreamSecureTransport()){
        printf("Started TLS in upstream\n");
        waiting_for_upTls = false;
        read_callbacks_->injectReadDataToFilterChain(second_temp, false);
        return Network::FilterStatus::StopIteration;
    }
    else{
        //printf("Failed to start upstream TLS\n");
    }*/

  if (sniffing_) {
    write_buffer_.add(data);
    doDecode(write_buffer_);
  }

  //return Network::FilterStatus::StopIteration;
  return Network::FilterStatus::Continue;
}

void MySQLFilter::doDecode(Buffer::Instance& buffer) {
  // Clear dynamic metadata.
  envoy::config::core::v3::Metadata& dynamic_metadata =
      read_callbacks_->connection().streamInfo().dynamicMetadata();
  auto& metadata =
      (*dynamic_metadata.mutable_filter_metadata())[NetworkFilterNames::get().MySQLProxy];
  metadata.mutable_fields()->clear();

  if (!decoder_) {
    decoder_ = createDecoder(*this);
  }

  try {
    decoder_->onData(buffer);
  } catch (EnvoyException& e) {
    ENVOY_LOG(info, "mysql_proxy: decoding error: {}", e.what());
    config_->stats_.decoder_errors_.inc();
    sniffing_ = false;
    read_buffer_.drain(read_buffer_.length());
    write_buffer_.drain(write_buffer_.length());
  }
}

DecoderPtr MySQLFilter::createDecoder(DecoderCallbacks& callbacks) {
  return std::make_unique<DecoderImpl>(callbacks);
}

void MySQLFilter::onProtocolError() { config_->stats_.protocol_errors_.inc(); }

void MySQLFilter::onNewMessage(MySQLSession::State state) {
  if (state == MySQLSession::State::ChallengeReq) {
    config_->stats_.login_attempts_.inc();
  }
}

void MySQLFilter::onClientLogin(ClientLogin& client_login) {
  if (client_login.isSSLRequest()) {
    config_->stats_.upgraded_to_ssl_.inc();
  }
}

void MySQLFilter::onClientLoginResponse(ClientLoginResponse& client_login_resp) {
  if (client_login_resp.getRespCode() == MYSQL_RESP_AUTH_SWITCH) {
    config_->stats_.auth_switch_request_.inc();
  } else if (client_login_resp.getRespCode() == MYSQL_RESP_ERR) {
    config_->stats_.login_failures_.inc();
  }
}

void MySQLFilter::onMoreClientLoginResponse(ClientLoginResponse& client_login_resp) {
  if (client_login_resp.getRespCode() == MYSQL_RESP_ERR) {
    config_->stats_.login_failures_.inc();
  }
}

void MySQLFilter::onCommand(Command& command) {
  if (!command.isQuery()) {
    return;
  }

  // Parse a given query
  envoy::config::core::v3::Metadata& dynamic_metadata =
      read_callbacks_->connection().streamInfo().dynamicMetadata();
  ProtobufWkt::Struct metadata(
      (*dynamic_metadata.mutable_filter_metadata())[NetworkFilterNames::get().MySQLProxy]);

  auto result = Common::SQLUtils::SQLUtils::setMetadata(command.getData(),
                                                        decoder_->getAttributes(), metadata);

  ENVOY_CONN_LOG(trace, "mysql_proxy: query processed {}, result {}, cmd type {}",
                 read_callbacks_->connection(), command.getData(), result,
                 static_cast<int>(command.getCmd()));

  if (!result) {
    config_->stats_.queries_parse_error_.inc();
    return;
  }
  config_->stats_.queries_parsed_.inc();

  read_callbacks_->connection().streamInfo().setDynamicMetadata(
      NetworkFilterNames::get().MySQLProxy, metadata);
}

Network::FilterStatus MySQLFilter::onNewConnection() {
  config_->stats_.sessions_.inc();
  /*if(read_callbacks_->connection().startSecureTransport()){
      printf("SSL established\n");
  }

  if(read_callbacks_->startUpstreamSecureTransport()){
      printf("Started TLS in upstream\n");
  }
  else{
      printf("Failed to start upstream TLS\n");
  }*/

  //return Network::FilterStatus::StopIteration;
  return Network::FilterStatus::Continue;
}


Buffer::OwnedImpl MySQLFilter::getClientHelloPacket()
{

  Buffer::OwnedImpl client_hello_buffer;
  if(shouldEncryptUpstream()){
    uint32_t tmp = 0x20000001;
    client_hello_buffer.writeBEInt<uint32_t>(tmp);
    // tmp = 0x85ae7f00;
    // tmp = 0x85aeff19;
    uint8_t tmp8;
    tmp8 = 0x85;
    client_hello_buffer.writeBEInt<uint8_t>(tmp8);
    tmp8 = 0xae;
    client_hello_buffer.writeBEInt<uint8_t>(tmp8);
    tmp8 = 0xff;
    client_hello_buffer.writeBEInt<uint8_t>(tmp8);
    tmp8 = 0x19;
    client_hello_buffer.writeBEInt<uint8_t>(tmp8);

    // client_hello_buffer.writeBEInt<uint32_t>(tmp);
    
    tmp = 0x00000001;
    client_hello_buffer.writeBEInt<uint32_t>(tmp);
    // uint64_t tmp_64 = 0x2100000000000000;
    uint64_t tmp_64 = 0xff00000000000000;
    client_hello_buffer.writeBEInt<uint64_t>(tmp_64);
    tmp_64 = 0;
    client_hello_buffer.writeBEInt<uint64_t>(tmp_64);
    client_hello_buffer.writeBEInt<uint64_t>(tmp_64);

    /*uint8_t ssl_req[] = {

        0x20, 0x00, 0x00, 0x01,

        0x85, 0xae,0x7f, 0x00,                            ff,19

        0x00, 0x00, 0x00, 0x01,

        0x21,

        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    for(int i = 0;i<36;i++){
      client_hello_buffer.writeBEInt<uint8_t>(ssl_req[i]);
    }*/

  }

  return client_hello_buffer;
}

bool MySQLFilter::shouldEncryptUpstream() {
  return config_->upstream_tls_;
}

bool MySQLFilter::shouldTerminateDownstreamTLS() {
  return config_->terminate_downstream_tls_;
}

void MySQLFilter::sendUpstream(Buffer::Instance& data) {
  read_callbacks_->injectReadDataToFilterChain(data,false);
}

void MySQLFilter::printData(Buffer::Instance& data, int len=-1) {

  int tmplen = data.length();

  if(len<0)len = tmplen;
  else len = std::min(len, tmplen);
  std::cout<< "PRINTING DATA BYTE PHASE     \n\n\n"<<std::endl;
  Buffer::OwnedImpl temp;
  temp.add(data);
  //Buffer::RawSlice slices[100];
  std::string tmpB;
  int bytes_to_read = temp.length();
  tmpB.assign(std::string(static_cast<char*>(data.linearize(bytes_to_read)), bytes_to_read));
  for(int ii = 0;ii<len;ii++){
    auto a = tmpB[ii];
    std::cout<< ii<<std::endl;
    auto b = uint8_t (a);
    auto c = uint(a);
    std::cout<<"a:   "<<a<< "    " <<b<< "   "<< c <<std::endl;
    for(int i = 0;i<8;i++){
      if(b&(1<<i)){
        std::cout<< " 1";
      }
      else{
        std::cout<< " 0";
      }
    }
    std::cout<<std::endl;
  }
}

Buffer::OwnedImpl MySQLFilter::getDataWithNewIndex(Buffer::OwnedImpl data, uint8_t changeIndex, bool decrease) {

  Buffer::OwnedImpl returnData;
  int sz = data.length();

  for(int i = 0;i<3;i++){
    uint8_t tmpByt = data.peekBEInt<uint8_t>(i);
    returnData.writeBEInt<uint8_t>(tmpByt);
  }

  uint8_t indx = data.peekBEInt<uint8_t>(3);
  if(!decrease) {
    indx += changeIndex;
  }
  else {
    indx -= changeIndex;
  }
  returnData.writeBEInt<uint8_t>(indx);

  for(int i = 4;i<sz;i++){

    uint8_t a = data.peekBEInt<uint8_t>(i);
    if(i==5){
      uint8_t bit4 = 0x8;

      a ^= bit4;

    }

    returnData.writeBEInt<uint8_t>(a);
  }

  return returnData;
}

Buffer::OwnedImpl MySQLFilter::changeBufferIdx(Buffer::OwnedImpl data, uint8_t changeIndex, bool decrease) {

  Buffer::OwnedImpl returnData;
  int sz = data.length();

  for(int i = 0;i<3;i++){
    uint8_t tmpByt = data.peekBEInt<uint8_t>(i);
    returnData.writeBEInt<uint8_t>(tmpByt);
  }

  uint8_t indx = data.peekBEInt<uint8_t>(3);
  if(!decrease) {
    indx += changeIndex;
  }
  else {
    indx -= changeIndex;
  }
  returnData.writeBEInt<uint8_t>(indx);

  for(int i = 4;i<sz;i++){

    uint8_t a = data.peekBEInt<uint8_t>(i);
    returnData.writeBEInt<uint8_t>(a);
  }

  return returnData;
}

Buffer::OwnedImpl MySQLFilter::changeBufferIdxForWrite(Buffer::OwnedImpl data, uint8_t changeIndex, bool decrease) {

  Buffer::OwnedImpl returnData;
  int sz = data.length();

  for(int i = 0;i<3;i++){
    uint8_t tmpByt = data.peekBEInt<uint8_t>(i);
    returnData.writeBEInt<uint8_t>(tmpByt);
  }

  uint8_t indx = data.peekBEInt<uint8_t>(3);
  if(!decrease) {
    indx += changeIndex;
  }
  else {
    indx -= changeIndex;
  }
  returnData.writeBEInt<uint8_t>(indx);

  for(int i = 4;i<sz;i++){

    uint8_t a = data.peekBEInt<uint8_t>(i);
    if(i==9){
      a ^= 0x7;
    }
    returnData.writeBEInt<uint8_t>(a);
  }

  return returnData;
}


Buffer::OwnedImpl MySQLFilter::manipulateData(Buffer::OwnedImpl data, uint8_t changeIndex, bool decrease) {
  Buffer::OwnedImpl returnData;
  int sz = data.length();

  for(int i = 0;i<3 + 36;i++){
    uint8_t tmpByt = data.peekBEInt<uint8_t>(i);
    returnData.writeBEInt<uint8_t>(tmpByt);
  }

  uint8_t indx = data.peekBEInt<uint8_t>(3+36);
  if(!decrease) {
    indx += changeIndex;
  }
  else {
    indx -= changeIndex;
  }
  returnData.writeBEInt<uint8_t>(indx);

  for(int i = 4;i<sz;i++){

    uint8_t a = data.peekBEInt<uint8_t>(i);
    if(i==5+36){
      uint8_t bit4 = 0x8;

      a ^= bit4;

    }
    returnData.writeBEInt<uint8_t>(a);
  }

  return returnData;
}


/* Changes the client ssl flag to 1 in server hello packet V10.
 * Use this when there is a ssl connection request from downstream but no ssl in the upsream
*/
Buffer::OwnedImpl MySQLFilter::onSSLFlagInClientHello(Buffer::OwnedImpl data) {

  Buffer::OwnedImpl returnData;
  int sz = data.length();
  int i;

  for(i = 0;i<4;i++){
    uint8_t tmpByt = data.peekBEInt<uint8_t>(i);
    returnData.writeBEInt<uint8_t>(tmpByt);
  }

  for(i = 4;i<sz;i++){
    uint8_t a = data.peekBEInt<uint8_t>(i);
    returnData.writeBEInt<uint8_t>(a);
    if(a==0x0){
      break;
    }
  }

  int j = i + 14;

  for(i++;i<=j;i++){
    uint8_t a = data.peekBEInt<uint8_t>(i);
    returnData.writeBEInt<uint8_t>(a);
  }

  uint8_t b = data.peekBEInt<uint8_t>(i);
  b |= 0x8;
  returnData.writeBEInt<uint8_t>(b);

  for(i++;i<sz;i++){
    uint8_t a = data.peekBEInt<uint8_t>(i);
    returnData.writeBEInt<uint8_t>(a);
  }

  return returnData;
}


} // namespace MySQLProxy
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
