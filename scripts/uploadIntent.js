Java.perform(function () {
    var MainActivity = Java.use('com.android.fridaplay.MainActivity');  

    MainActivity.onCreate.overload('android.os.Bundle').implementation = function (bundle) {
        this.onCreate(bundle);

        var String = Java.use('java.lang.String');
        var Intent = Java.use('android.content.Intent');
        var intent = Intent.$new();
        intent.setAction(String.$new('android.intent.action.PICK'));  
        intent.setType('image/*');  

        this.startActivityForResult(intent, 1);

        console.log("Image picker intent launched!");

    };

    MainActivity.onActivityResult.overload('int', 'int', 'android.content.Intent').implementation = function (requestCode, resultCode, data) {
        if (requestCode === 1) {
            if (resultCode === -1) {  // -1 corresponds to RESULT_OK (success)
                console.log("Image picker result: SUCCESS");

                var uri = data.getData(); 
                console.log("Selected image URI: " + uri.toString()); 

                // 'this' here refers to the current activity (MainActivity)
                var activity = this;

                // Decode the image from the URI
                var BitmapFactory = Java.use('android.graphics.BitmapFactory');
                var ContentResolver = activity.getContentResolver();  
                var inputStream = ContentResolver.openInputStream(uri);
                var bitmap = BitmapFactory.decodeStream(inputStream); 

                console.log("Bitmap width: " + bitmap.getWidth());
                console.log("Bitmap height: " + bitmap.getHeight());
                
            } else {
                console.log("Image picker result: CANCELED or ERROR");
            }
        }

        // Call the original onActivityResult method
        this.onActivityResult(requestCode, resultCode, data);
    };
});
