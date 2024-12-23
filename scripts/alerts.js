// Load the Frida module
Java.perform(function () {
    // Get a reference to the MainActivity class
    var MainActivity = Java.use('com.android.fridaplay.MainActivity');

    // Hook into the onCreate method of MainActivity
    MainActivity.onCreate.overload('android.os.Bundle').implementation = function (bundle) {
        // Call the original onCreate method
        this.onCreate(bundle);

        // Show the alert using Android's AlertDialog
        var AlertDialog = Java.use('android.app.AlertDialog$Builder');

        // Use the current activity as context
        var activity = this;

        var dialog = AlertDialog.$new(activity);
        dialog.setMessage(Java.use('java.lang.String').$new("Hey, how you doing today?"));
        dialog.setCancelable(true);
        dialog.setPositiveButton(Java.use('java.lang.String').$new("OK"), null);

        // Display the dialog
        Java.scheduleOnMainThread(function() {
            dialog.show();
        });
    };
});
