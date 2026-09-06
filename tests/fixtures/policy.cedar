entity Agent::"ap-clerk" {} ;
permit(principal == Agent::"ap-clerk", action == Action::"pay_invoice", resource) when { resource.vendor == "globex" };
