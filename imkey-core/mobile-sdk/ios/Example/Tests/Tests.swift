import XCTest
import imKeyConnector

class Tests: XCTestCase {
  
  override func setUp() {
    super.setUp()
    // Put setup code here. This method is called before the invocation of each test method in the class.
  }
  
  override func tearDown() {
    // Put teardown code here. This method is called after the invocation of each test method in the class.
    super.tearDown()
  }
  
  func testExample() {
    // This is an example of a functional test case.
    XCTAssert(true, "Pass")
    let str = "04D5C69633019405D6E5F825AED15F36CA2142C4908D93ACB1E1DA1923EA122B3D01D73FA45ECCCCD6CFB755478E32D51D748C9C7CCD8B9E5F4F0B75D648BA3252530090700276C0318D171E50399C360CCF29CA972B35ACD1827F623985B42BF89000"
    Log.d(str.key_substring(from: 2).key_substring(to: 64))
  }
  
  
  
  func testPerformanceExample() {
    // This is an example of a performance test case.
    self.measure() {
      // Put the code you want to measure the time of here.
    }
  }
}
