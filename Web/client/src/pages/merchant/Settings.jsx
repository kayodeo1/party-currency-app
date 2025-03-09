import React, { useState } from "react";
import { MerchantSidebar } from "@/components/merchant/MerchantSidebar";
import MerchantHeader from "@/components/merchant/MerchantHeader";
import { Pencil } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/switch";

export default function Settings() {
  const [isAccountDisabled, setIsAccountDisabled] = useState(false);
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);

  return (
    <div className="bg-gray-50 min-h-screen">
      <MerchantSidebar
        isOpen={isMobileMenuOpen}
        onClose={() => setIsMobileMenuOpen(false)}
      />

      <div className="flex flex-col md:pl-64 min-h-screen">
        <MerchantHeader
          toggleMobileMenu={() => setIsMobileMenuOpen(!isMobileMenuOpen)}
        />

        <main className="flex-1 p-4 md:p-8">
          <div className="mx-auto max-w-2xl">
            <div className="space-y-6 bg-white shadow p-6 rounded-lg">
              {/* Location Address */}
              <div className="flex justify-between items-center py-4 border-b">
                <div>
                  <h3 className="font-medium text-lg">Location Address</h3>
                </div>
                <Button
                  variant="ghost"
                  size="icon"
                  className="text-blueSecondary hover:text-bluePrimary"
                >
                  <Pencil className="w-5 h-5" />
                </Button>
              </div>

              {/* Disable Account */}
              <div className="flex justify-between items-center py-4 border-b">
                <div>
                  <h3 className="font-medium text-lg">
                    Disable Merchant Account
                  </h3>
                </div>
                <Switch
                  checked={isAccountDisabled}
                  onCheckedChange={setIsAccountDisabled}
                />
              </div>

              {/* Phone Number */}
              <div className="flex justify-between items-center py-4 border-b">
                <div>
                  <h3 className="font-medium text-lg">Phone Number</h3>
                </div>
                <Button
                  variant="ghost"
                  size="icon"
                  className="text-blueSecondary hover:text-bluePrimary"
                >
                  <Pencil className="w-5 h-5" />
                </Button>
              </div>

              {/* Password */}
              <div className="flex justify-between items-center py-4 border-b">
                <div>
                  <h3 className="font-medium text-lg">Password</h3>
                </div>
                <Button
                  variant="ghost"
                  size="icon"
                  className="text-blueSecondary hover:text-bluePrimary"
                >
                  <Pencil className="w-5 h-5" />
                </Button>
              </div>
            </div>
          </div>
        </main>
      </div>
    </div>
  );
}
