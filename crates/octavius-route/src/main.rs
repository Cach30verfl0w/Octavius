use octavius_route::{
    linux::LinuxRouteTable,
    RouteTable,
};

#[tokio::main]
async fn main() {
    let route_table = LinuxRouteTable::new().unwrap();
    for route in route_table.all().await.unwrap() {
        println!("{:?}", route);
    }
}
