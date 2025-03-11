use octavius_route::RouteTable;
use octavius_route::windows_sys::WindowsRouteTable;

#[tokio::main]
async fn main() {
    let route_table = WindowsRouteTable::new().unwrap();
    for route in route_table.all().await.unwrap() {
        println!("{:?}", route);
    }
}
