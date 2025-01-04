import React, { useEffect, useContext } from "react";
import { Info } from "lucide-react";
import { Link, useNavigate } from "react-router-dom"; // Import Link for navigation
import { USER_PROFILE_CONTEXT } from "../context";
import DashboardSidebar from "../components/DashboardSidebar"; // Import Sidebar
import DashboardHeader from "../components/DashboardHeader"; // Import Header
import StatsCard from "../components/StatsCard"; // Import StatsCard

export default function Dashboard() {
  const { userProfile } = useContext(USER_PROFILE_CONTEXT);
  const navigate = useNavigate();

  // useEffect(() => {
  //   if (!userProfile) {
  //     navigate("/login");
  //   }
  // }, [userProfile, navigate]);

  return (
    <div className="bg-white min-h-screen">
      {/* Sidebar */}
      <DashboardSidebar />

      {/* Main Content */}
      <div className="pl-64">
        {/* Header */}
        <DashboardHeader />

        {/* Main Section */}
        <main className="p-6">
          {/* Stats Cards */}
          <div className="gap-6 grid grid-cols-2 mb-8">
            <StatsCard
              label="Total Transaction Amount"
              value="₦500,000.00"
              status="Host"
            />
            <StatsCard label="Total Event Hosted" value="2" />
          </div>

          {/* Transaction History Section */}
          <section>
            <h2 className="mb-6 font-semibold text-xl">Transaction History</h2>

            {/* Empty State */}
            <div className="flex flex-col justify-center items-center py-12 text-center">
              <Info className="mb-4 w-12 h-12 text-[#F5B014]" />
              <p className="mb-4 text-gray-600">
                Yet to perform any transaction
              </p>
              <Link
                to="/create-event"
                className="text-[#F5B014] hover:underline"
              >
                Create an event
              </Link>
            </div>
          </section>
        </main>
      </div>
    </div>
  );
}
