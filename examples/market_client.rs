use cfix::{types::{ConnectionHandler, DepthPrice, IncrementalRefresh, MarketDataHandler, SpotPrice}, MarketClient, HmacSHA256Base64Utils};
use std::{collections::HashMap, env, error::Error, sync::Arc};
use chrono::Utc;
use cfix::HmacSHA256Base64Utils::sign;
// Usage example:
//

struct Handler;

#[async_trait::async_trait]
impl ConnectionHandler for Handler {
    async fn on_connect(&self) {
        log::info!("in handler : connected");
    }
    async fn on_logon(&self) {
        log::info!("in handler : logon");
    }
    async fn on_disconnect(&self) {
        log::info!("in handler : disconnected");
    }
}

#[async_trait::async_trait]
impl MarketDataHandler for Handler {
    async fn on_price_of(&self, symbol_id: u32, price: SpotPrice) {
        log::info!("in handler : symbol({}) - price: {:?}", symbol_id, price);
    }
    async fn on_market_depth_full_refresh(
        &self,
        symbol_id: u32,
        full_depth: HashMap<String, DepthPrice>,
    ) {
        log::info!(
            "in handle : symbol({}) - full depth: {:?}",
            symbol_id,
            full_depth
        );
    }
    async fn on_market_depth_incremental_refresh(&self, refresh: Vec<IncrementalRefresh>) {
        log::info!("in handle : incremental refreush: {:?}", refresh);
    }

    async fn on_accpeted_spot_subscription(&self, symbol_id: u32) {
        log::info!("Spot subscription accepted {}", symbol_id);
    }
    async fn on_accpeted_depth_subscription(&self, symbol_id: u32) {
        log::info!("Depth subscription accepted {}", symbol_id);
    }

    async fn on_rejected_spot_subscription(&self, symbol_id: u32, err_msg: String) {
        log::info!("Spot subscription rejected {} - {}", symbol_id, err_msg);
    }
    async fn on_rejected_depth_subscription(&self, symbol_id: u32, err_msg: String) {
        log::info!("Depth subscription rejected {} - {}", symbol_id, err_msg);
    }
}



#[async_std::main]
async fn main() -> Result<(), Box<dyn Error>> {
    dotenv::dotenv().ok();
    // env_logger::init();
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug")).init();

    let host = "fix-ord.exchange.coinbase.com".to_string();
    let username = "test".to_string();
    let password = "7t6oz9lezfm".to_string();
    let sender_comp_id = "9b695942ca7f212563b6e27e6229b2bf".to_string();

    let handler = Arc::new(Handler {});
    let mut client = MarketClient::new(host, username, password, sender_comp_id, None);
    client.register_connection_handler_arc(handler.clone());
    client.register_market_handler_arc(handler.clone());
    // connect and logon
    client.connect().await?;
    if client.is_connected() {
        let symbol_id = 11;
        client.subscribe_spot(symbol_id).await?;
        client.subscribe_spot(1).await?;
        log::info!("spot subsciption requested");
        async_std::task::sleep(std::time::Duration::from_secs(3)).await;

        // try to subscription again
        // if let Err(err) = client.subscribe_spot(symbol_id).await {
        //     log::error!("{}", err);
        // }
        //
        log::info!(
            "The prices of symbol_id({}) is {:?}",
            symbol_id,
            client.price_of(symbol_id).await?
        );

        // TEST invalid symbol
        // log::info!("Test subscription with invalid symbol");
        // client.subscribe_spot(500000).await?;
        // async_std::task::sleep(std::time::Duration::from_secs(2)).await;

        log::info!(
            "Spot subscription list : {:?}",
            client.spot_subscription_list().await
        );

        client.unsubscribe_spot(symbol_id).await?;
        client.unsubscribe_spot(1).await?;
        log::info!("Spot unsubscribed");

        // try to unsubscription again
        // if let Err(err) = client.unsubscribe_spot(symbol_id).await {
        //     log::error!("{}", err);
        // }
        //
        log::info!(
            "Spot subscription list : {:?}",
            client.spot_subscription_list().await
        );
        async_std::task::sleep(std::time::Duration::from_secs(2)).await;

        //

        //

        // ======================================
        // depth market
        //
        client.subscribe_depth(symbol_id).await?;
        client.subscribe_depth(3).await?;
        log::info!("depth subsciption requested");
        async_std::task::sleep(std::time::Duration::from_secs(5)).await;

        // try to subscription again
        // if let Err(err) = client.subscribe_depth(symbol_id).await {
        //     log::error!("{}", err);
        // }

        log::info!(
            "The depth data of symbol_id({}) is {:?}",
            symbol_id,
            client.depth_data(symbol_id).await?
        );

        log::info!(
            "Depth subscription list : {:?}",
            client.depth_subscription_list().await
        );

        log::info!("Depth data of symbol(3) - {:?}", client.depth_data(3).await);

        // unsubscribe
        client.unsubscribe_depth(symbol_id).await?;
        client.unsubscribe_depth(3).await?;
        log::info!("Depth unsubscribed");

        log::info!(
            "Depth subscription list : {:?}",
            client.depth_subscription_list().await
        );

        // try to unsubscription again
        // if let Err(err) = client.unsubscribe_depth(symbol_id).await {
        //     log::error!("{}", err);
        // }

        // for test
        // async_std::task::sleep(std::time::Duration::from_secs(500)).await;
    }

    // disconnect
    client.disconnect().await?;
    async_std::task::sleep(std::time::Duration::from_secs(2)).await;

    Ok(())
}

